// SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
// SPDX-License-Identifier: MIT

// Package observer exposes a Hubble-compatible gRPC API
// (cilium.observer.Observer) backed by microseg's flow events.
//
// This is the API that hubble-relay and hubble-ui speak. Implementing
// the same proto contract means the unmodified upstream UI can render
// our workstation-scale flow graph, with the (cgroup_id, unit) identity
// surfaced as endpoint labels.
//
// Scope of the PoC: GetFlows (streaming, with `since/last` semantics),
// ServerStatus, GetNodes. Other RPCs return Unimplemented — hubble-ui
// degrades gracefully.
package observer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	relaypb "github.com/cilium/cilium/api/v1/relay"
)

// TLSConfig describes the optional transport credentials for the gRPC
// observer. Zero value (all fields empty) means plaintext — the right
// default for the Unix-socket setup. For a TCP listener, set CertFile +
// KeyFile at minimum. Set ClientCAFile to require mTLS.
//
// See SECURITY-AUDIT.md §F-1 for why TCP listener without TLS is loud.
type TLSConfig struct {
	CertFile      string // server cert (PEM)
	KeyFile       string // server key (PEM)
	ClientCAFile  string // CA bundle for verifying client certs (mTLS)
	RequireClient bool   // require + verify a valid client cert
}

func (t TLSConfig) enabled() bool {
	return t.CertFile != "" && t.KeyFile != ""
}

func (t TLSConfig) buildCreds() (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert/key: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if t.ClientCAFile != "" {
		caPEM, err := os.ReadFile(t.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("client CA %q parsed no certificates", t.ClientCAFile)
		}
		cfg.ClientCAs = pool
		if t.RequireClient {
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			cfg.ClientAuth = tls.VerifyClientCertIfGiven
		}
	} else if t.RequireClient {
		return nil, fmt.Errorf("RequireClient=true needs ClientCAFile to be set")
	}
	return credentials.NewTLS(cfg), nil
}

// Server holds the gRPC listener, the bounded ring of recent flows, and
// the set of live subscribers (one per active GetFlows stream).
type Server struct {
	observerpb.UnimplementedObserverServer

	hostname string
	mu       sync.Mutex
	ring     []*flowpb.Flow
	ringHead int
	ringSize int

	subs map[chan *flowpb.Flow]struct{}
	gs   *grpc.Server
}

// New builds a Server with `bufSize` recent-flow capacity.
func New(bufSize int) *Server {
	host, _ := os.Hostname()
	return &Server{
		hostname: host,
		ring:     make([]*flowpb.Flow, bufSize),
		ringSize: bufSize,
		subs:     map[chan *flowpb.Flow]struct{}{},
	}
}

// Publish records a flow into the ring buffer and fans it out to live
// subscribers. Called from the ringbuf consumer goroutine.
func (s *Server) Publish(f *flowpb.Flow) {
	s.mu.Lock()
	s.ring[s.ringHead] = f
	s.ringHead = (s.ringHead + 1) % s.ringSize
	subs := make([]chan *flowpb.Flow, 0, len(s.subs))
	for c := range s.subs {
		subs = append(subs, c)
	}
	s.mu.Unlock()

	for _, c := range subs {
		select {
		case c <- f:
		default:
			// Drop on slow subscribers: a saturated UI must not back-pressure
			// the datapath. Hubble UI itself behaves the same way.
		}
	}
}

// Serve binds to `addr` (Unix socket path prefixed with "unix:" or a
// TCP host:port) and blocks until ctx is cancelled. When `tlsCfg` is
// non-zero (CertFile + KeyFile set) the server wraps the listener with
// TLS — required for any TCP listener that's reachable beyond the
// loopback interface. See SECURITY-AUDIT.md §F-1.
func (s *Server) Serve(ctx context.Context, addr string, tlsCfg TLSConfig) error {
	network := "tcp"
	target := addr
	if len(addr) > 5 && addr[:5] == "unix:" {
		network, target = "unix", addr[5:]
		_ = os.Remove(target)
	}
	ln, err := net.Listen(network, target)
	if err != nil {
		return err
	}

	var opts []grpc.ServerOption
	if tlsCfg.enabled() {
		creds, err := tlsCfg.buildCreds()
		if err != nil {
			return fmt.Errorf("tls: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}
	s.gs = grpc.NewServer(opts...)
	observerpb.RegisterObserverServer(s.gs, s)

	go func() {
		<-ctx.Done()
		s.gs.GracefulStop()
	}()
	return s.gs.Serve(ln)
}

// --- Observer service implementation ---

func (s *Server) ServerStatus(ctx context.Context, _ *observerpb.ServerStatusRequest) (*observerpb.ServerStatusResponse, error) {
	s.mu.Lock()
	n := uint64(0)
	for _, f := range s.ring {
		if f != nil {
			n++
		}
	}
	s.mu.Unlock()
	return &observerpb.ServerStatusResponse{
		NumFlows:    n,
		MaxFlows:    uint64(s.ringSize),
		SeenFlows:   n,
		UptimeNs:    uint64(time.Since(startTime).Nanoseconds()),
		NumConnectedNodes:   wrapperspb.UInt32(1),
		NumUnavailableNodes: wrapperspb.UInt32(0),
		Version:     "nixos-microsegebpf/0.1 (hubble-compat)",
	}, nil
}

func (s *Server) GetNodes(ctx context.Context, _ *observerpb.GetNodesRequest) (*observerpb.GetNodesResponse, error) {
	return &observerpb.GetNodesResponse{
		Nodes: []*observerpb.Node{{
			Name:    s.hostname,
			Version: "nixos-microsegebpf/0.1",
			State:   relaypb.NodeState_NODE_CONNECTED,
		}},
	}, nil
}

// GetFlows streams (a) the requested chunk of historical flows from the
// ring, then (b) live flows as they arrive, until the client disconnects
// or `Number` has been reached.
func (s *Server) GetFlows(req *observerpb.GetFlowsRequest, stream observerpb.Observer_GetFlowsServer) error {
	live := make(chan *flowpb.Flow, 256)
	follow := req.GetFollow()
	limit := req.GetNumber()
	if limit == 0 && !follow {
		limit = 100 // sensible default for one-shot queries
	}

	if follow {
		s.mu.Lock()
		s.subs[live] = struct{}{}
		s.mu.Unlock()
		defer func() {
			s.mu.Lock()
			delete(s.subs, live)
			s.mu.Unlock()
		}()
	}

	// Replay the ring oldest-first, up to `limit` if not following.
	s.mu.Lock()
	snap := append([]*flowpb.Flow(nil), s.ring[s.ringHead:]...)
	snap = append(snap, s.ring[:s.ringHead]...)
	s.mu.Unlock()

	sent := uint64(0)
	for _, f := range snap {
		if f == nil {
			continue
		}
		if err := stream.Send(&observerpb.GetFlowsResponse{
			ResponseTypes: &observerpb.GetFlowsResponse_Flow{Flow: f},
			NodeName:      s.hostname,
			Time:          f.Time,
		}); err != nil {
			return err
		}
		sent++
		if !follow && limit > 0 && sent >= limit {
			return nil
		}
	}

	if !follow {
		return nil
	}

	for {
		select {
		case <-stream.Context().Done():
			return status.Error(codes.Canceled, "client disconnected")
		case f, ok := <-live:
			if !ok {
				return nil
			}
			if err := stream.Send(&observerpb.GetFlowsResponse{
				ResponseTypes: &observerpb.GetFlowsResponse_Flow{Flow: f},
				NodeName:      s.hostname,
				Time:          f.Time,
			}); err != nil {
				return err
			}
		}
	}
}

var startTime = time.Now()
