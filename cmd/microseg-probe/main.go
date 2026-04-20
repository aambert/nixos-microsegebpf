// SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
// SPDX-License-Identifier: MIT
//
// microseg-probe is a tiny Hubble client used to verify that the agent's
// observer.proto implementation answers correctly. It mirrors the calls
// hubble-ui issues at startup (ServerStatus + GetFlows stream).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
)

func main() {
	addr := flag.String("addr", "unix:/run/microseg/hubble.sock", "agent observer address")
	follow := flag.Bool("follow", false, "stream live flows after the historical replay")
	limit := flag.Uint64("limit", 5, "max historical flows to print (0 = all)")
	tlsCA := flag.String("tls-ca", "", "path to CA bundle (PEM) used to verify the server certificate; setting this enables TLS")
	tlsCert := flag.String("tls-cert", "", "path to client certificate (PEM) for mTLS — pair with -tls-key")
	tlsKey := flag.String("tls-key", "", "path to client private key (PEM) for mTLS — pair with -tls-cert")
	tlsServerName := flag.String("tls-server-name", "", "expected SAN on the server certificate (defaults to the host portion of -addr)")
	tlsInsecure := flag.Bool("tls-insecure", false, "skip server certificate verification (DEV ONLY — never use against a production observer)")
	flag.Parse()

	dialer := grpc.WithContextDialer(func(ctx context.Context, target string) (net.Conn, error) {
		network, t := splitAddr(target)
		var d net.Dialer
		return d.DialContext(ctx, network, t)
	})

	creds, err := buildClientCreds(*addr, *tlsCA, *tlsCert, *tlsKey, *tlsServerName, *tlsInsecure)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}

	conn, err := grpc.NewClient(*addr,
		grpc.WithTransportCredentials(creds),
		dialer,
	)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	c := observerpb.NewObserverClient(conn)

	st, err := c.ServerStatus(context.Background(), &observerpb.ServerStatusRequest{})
	if err != nil {
		log.Fatalf("ServerStatus: %v", err)
	}
	fmt.Printf("=== ServerStatus ===\n")
	fmt.Printf("  Version:        %s\n", st.Version)
	fmt.Printf("  NumFlows:       %d / %d\n", st.NumFlows, st.MaxFlows)
	fmt.Printf("  ConnectedNodes: %d\n", st.GetNumConnectedNodes().GetValue())
	fmt.Printf("  Uptime:         %v\n", time.Duration(st.UptimeNs))

	nodes, err := c.GetNodes(context.Background(), &observerpb.GetNodesRequest{})
	if err != nil {
		log.Fatalf("GetNodes: %v", err)
	}
	fmt.Printf("=== GetNodes ===\n")
	for _, n := range nodes.Nodes {
		fmt.Printf("  - name=%s state=%s version=%s\n", n.Name, n.State, n.Version)
	}

	stream, err := c.GetFlows(context.Background(), &observerpb.GetFlowsRequest{
		Number: *limit,
		Follow: *follow,
	})
	if err != nil {
		log.Fatalf("GetFlows: %v", err)
	}
	fmt.Printf("=== GetFlows (limit=%d, follow=%v) ===\n", *limit, *follow)
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("Recv: %v", err)
		}
		f := resp.GetFlow()
		if f == nil {
			continue
		}
		sport, dport := l4Ports(f)
		fmt.Printf("  %-10s %-7s %s:%d -> %s:%d  src=%s dst=%s policy=%d\n",
			f.Verdict.String(),
			f.TrafficDirection.String(),
			f.GetIP().GetSource(), sport,
			f.GetIP().GetDestination(), dport,
			endpointLabel(f.GetSource()),
			endpointLabel(f.GetDestination()),
			f.GetEventType().GetSubType(),
		)
	}
}

func splitAddr(s string) (network, target string) {
	if strings.HasPrefix(s, "unix:") {
		return "unix", strings.TrimPrefix(s, "unix:")
	}
	return "tcp", s
}

// buildClientCreds chooses transport credentials based on the supplied
// flags. Defaults to insecure for the Unix-socket case (kernel mediates
// access via the socket's mode bits, no need for TLS). Any non-empty
// TLS flag opts into a tls.Config — caFile pins the server cert,
// cert+key add an mTLS client identity, insecure disables verification.
func buildClientCreds(addr, caFile, certFile, keyFile, serverName string, insecureSkipVerify bool) (credentials.TransportCredentials, error) {
	tlsRequested := caFile != "" || certFile != "" || keyFile != "" || insecureSkipVerify
	if !tlsRequested {
		return insecure.NewCredentials(), nil
	}

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if insecureSkipVerify {
		cfg.InsecureSkipVerify = true
		fmt.Fprintln(os.Stderr, "WARN: -tls-insecure: skipping server certificate verification — never do this against a production observer")
	} else if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read -tls-ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("-tls-ca %q parsed no certificates", caFile)
		}
		cfg.RootCAs = pool
	}
	// If neither -tls-ca nor -tls-insecure is set, the system trust
	// store is used. That's fine for a publicly-trusted cert; for an
	// internal CA you want -tls-ca.

	if (certFile == "") != (keyFile == "") {
		return nil, fmt.Errorf("-tls-cert and -tls-key must be set together")
	}
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert/key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	if serverName != "" {
		cfg.ServerName = serverName
	} else {
		// gRPC's default ServerName is the dial address; for our
		// `host:port` form we strip the port to match a typical
		// SAN entry. unix: addresses are skipped (TLS over Unix
		// is unusual but supported).
		_, t := splitAddr(addr)
		if h, _, err := net.SplitHostPort(t); err == nil {
			cfg.ServerName = h
		}
	}

	return credentials.NewTLS(cfg), nil
}

func endpointLabel(ep *flowpb.Endpoint) string {
	if ep == nil {
		return "?"
	}
	return ep.ClusterName + "/" + ep.PodName
}

func l4Ports(f *flowpb.Flow) (uint32, uint32) {
	l4 := f.GetL4()
	if l4 == nil {
		return 0, 0
	}
	if t := l4.GetTCP(); t != nil {
		return t.SourcePort, t.DestinationPort
	}
	if u := l4.GetUDP(); u != nil {
		return u.SourcePort, u.DestinationPort
	}
	return 0, 0
}
