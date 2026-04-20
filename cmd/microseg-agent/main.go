// SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
// SPDX-License-Identifier: MIT

// microseg-agent is the per-host daemon: it loads the eBPF datapath, applies
// the policy file from disk, and serves the Hubble observer gRPC API on a
// local Unix socket so hubble-ui can render the workstation flow map.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	bpfobj "github.com/aambert/nixos-microsegebpf/bpf"
	"github.com/aambert/nixos-microsegebpf/pkg/identity"
	"github.com/aambert/nixos-microsegebpf/pkg/loader"
	"github.com/aambert/nixos-microsegebpf/pkg/observer"
	"github.com/aambert/nixos-microsegebpf/pkg/policy"
)

type flowEvent struct {
	TsNs      uint64 `json:"ts_ns"`
	CgroupID  uint64 `json:"cgroup_id"`
	Unit      string `json:"unit,omitempty"`
	Family    uint8  `json:"family"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   uint16 `json:"src_port"`
	DstPort   uint16 `json:"dst_port"`
	Protocol  uint8  `json:"protocol"`
	Direction string `json:"direction"`
	Verdict   string `json:"verdict"`
	PolicyID  uint32 `json:"policy_id"`
}

func ipString(b []byte, family uint8) string {
	if family == 4 {
		return net.IP(b[:4]).String()
	}
	return net.IP(b[:16]).String()
}

// unitCache maps cgroup_id → systemd unit name. Refreshed by the same
// timer that re-resolves selectors so the observer never lags behind by
// more than `resolveEvery`.
type unitCache struct {
	mu    sync.RWMutex
	units map[uint64]string
}

func (c *unitCache) refresh() {
	cgs, err := identity.Snapshot()
	if err != nil {
		return
	}
	m := make(map[uint64]string, len(cgs))
	for _, cg := range cgs {
		m[cg.ID] = cg.SystemdUnit
	}
	c.mu.Lock()
	c.units = m
	c.mu.Unlock()
}

func (c *unitCache) lookup(cgid uint64) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.units[cgid]
}

func main() {
	var (
		jsonLog          bool
		emitAllow        bool
		enforce          bool
		defaultEgress    string
		defaultIngrs     string
		policyPath       string
		resolveEvery     time.Duration
		dnsCacheTTL      time.Duration
		hubbleAddr       string
		hubbleBufSize    int
		hubbleTlsCert    string
		hubbleTlsKey     string
		hubbleTlsClientCA string
		hubbleTlsRequireClient bool
		tlsPortsRaw      string
		blockQuic        bool
	)
	flag.BoolVar(&jsonLog, "json", true, "emit flow events as JSON on stdout")
	flag.BoolVar(&emitAllow, "emit-allow", true, "emit ringbuf events even for ALLOW verdicts")
	flag.BoolVar(&enforce, "enforce", true, "honour drop verdicts in the loaded policies (false demotes every drop to log so the kernel still emits flow events but never returns SK_DROP — bake-in mode)")
	flag.StringVar(&defaultEgress, "default-egress", "allow", "default verdict for egress without policy match: allow|drop")
	flag.StringVar(&defaultIngrs, "default-ingress", "allow", "default verdict for ingress without policy match: allow|drop")
	flag.StringVar(&policyPath, "policy", "", "path to a YAML policy file (omit to disable policy)")
	flag.DurationVar(&resolveEvery, "resolve-every", 5*time.Second, "how often to re-resolve selectors against the cgroup tree")
	flag.DurationVar(&dnsCacheTTL, "dns-cache-ttl", 60*time.Second, "how long to cache FQDN→IP resolution for `host:` rules (0 = no cache, re-resolve on every Apply)")
	flag.StringVar(&hubbleAddr, "hubble-addr", "unix:/run/microseg/hubble.sock", "Hubble observer gRPC listen address (host:port or unix:/path)")
	flag.IntVar(&hubbleBufSize, "hubble-buffer", 4096, "number of recent flows kept in the observer ring buffer")
	flag.StringVar(&hubbleTlsCert, "hubble-tls-cert", "", "path to server TLS certificate (PEM) for the gRPC observer; required for any TCP listener that escapes loopback")
	flag.StringVar(&hubbleTlsKey, "hubble-tls-key", "", "path to server TLS private key (PEM) — must pair with -hubble-tls-cert")
	flag.StringVar(&hubbleTlsClientCA, "hubble-tls-client-ca", "", "path to CA bundle for verifying client certificates (mTLS) — empty = no client cert check")
	flag.BoolVar(&hubbleTlsRequireClient, "hubble-tls-require-client", false, "require + verify a valid client certificate (mTLS); ignored unless -hubble-tls-client-ca is also set")
	flag.StringVar(&tlsPortsRaw, "tls-ports", "443,8443", "comma-separated destination ports treated as TLS-bearing for SNI/ALPN peeking and QUIC blocking (max 8)")
	flag.BoolVar(&blockQuic, "block-quic", false, "drop UDP egress to any -tls-ports — forces QUIC clients to fall back to TCP/TLS where SNI matching works")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	l := loader.New()
	if err := l.Load(); err != nil {
		log.Error("load failed", "err", err)
		os.Exit(1)
	}
	if err := l.Attach(); err != nil {
		log.Error("attach failed", "err", err)
		_ = l.Close()
		os.Exit(1)
	}
	defer l.Close()

	tlsPorts, err := parseTlsPorts(tlsPortsRaw)
	if err != nil {
		log.Error("parse tls-ports", "raw", tlsPortsRaw, "err", err)
		os.Exit(1)
	}

	cfg := bpfobj.MicrosegDefaultCfg{
		DefaultEgressVerdict:  verdictFromName(defaultEgress),
		DefaultIngressVerdict: verdictFromName(defaultIngrs),
		EmitAllowEvents:       boolToU8(emitAllow),
		BlockQuic:             boolToU8(blockQuic),
		NumTlsPorts:           uint8(len(tlsPorts)),
	}
	for i, p := range tlsPorts {
		cfg.TlsPorts[i] = p
	}
	var k uint32 = 0
	if err := l.ConfigMap().Update(&k, &cfg, 0); err != nil {
		log.Error("init config map", "err", err)
		os.Exit(1)
	}

	log.Info("microseg attached",
		"cgroup", "/sys/fs/cgroup",
		"bpffs", "/sys/fs/bpf/microseg",
		"default_egress", defaultEgress,
		"default_ingress", defaultIngrs,
		"emit_allow", emitAllow,
	)

	cache := &unitCache{units: map[uint64]string{}}
	cache.refresh()

	// Bring up the cgroup tree watcher: inotify on every cgroupv2 dir
	// gives us sub-second reaction to new units (e.g. user logins,
	// browser launches). We keep `resolveEvery` as a safety-net fallback
	// in case inotify ever drops an event.
	cgw, err := identity.NewWatcher(log, 250*time.Millisecond)
	if err != nil {
		log.Error("cgroup watcher", "err", err)
		os.Exit(1)
	}
	defer cgw.Close()

	var stopSync chan<- struct{}
	if policyPath != "" {
		docs, err := policy.LoadFile(policyPath)
		if err != nil {
			log.Error("policy load failed", "path", policyPath, "err", err)
			os.Exit(1)
		}
		syncer := policy.NewSyncer(policy.Maps{
			EgressV4:    l.EgressV4Map(),
			IngressV4:   l.IngressV4Map(),
			EgressV6:    l.EgressV6Map(),
			IngressV6:   l.IngressV6Map(),
			TlsSniLpm:   l.TlsSniLpmMap(),
			TlsAlpnDeny: l.TlsAlpnDenyMap(),
		}, log)
		syncer.SetEnforce(enforce)
		syncer.SetDNSCacheTTL(dnsCacheTTL)
		if err := syncer.Apply(docs); err != nil {
			log.Error("initial policy apply failed", "err", err)
			os.Exit(1)
		}
		stopSync = syncer.Resolve(docs, cgw.Subscribe(), resolveEvery)
		log.Info("policy loaded",
			"path", policyPath, "docs", len(docs),
			"enforce", enforce,
			"fallback_resolve", resolveEvery, "watcher", "inotify")
	}

	// Refresh the unit cache on the same cgroup events as the policy
	// resolver, so the Hubble observer surfaces newly-spawned units
	// within ~250 ms (debounce window) of their creation.
	//
	// Important: Subscribe ONCE outside the loop. Calling Subscribe on
	// every iteration would leak channels (each call appends to the
	// watcher's subscriber list).
	cacheEvents := cgw.Subscribe()
	go func() {
		t := time.NewTicker(resolveEvery)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				cache.refresh()
			case <-cacheEvents:
				cache.refresh()
			}
		}
	}()

	// Bring up the Hubble observer gRPC server.
	obsCtx, obsCancel := context.WithCancel(context.Background())
	defer obsCancel()
	srv := observer.New(hubbleBufSize)
	if err := os.MkdirAll("/run/microseg", 0o755); err != nil && !os.IsExist(err) {
		log.Warn("mkdir /run/microseg", "err", err)
	}
	hubbleTls := observer.TLSConfig{
		CertFile:      hubbleTlsCert,
		KeyFile:       hubbleTlsKey,
		ClientCAFile:  hubbleTlsClientCA,
		RequireClient: hubbleTlsRequireClient,
	}
	// Loud warning at startup when a TCP listener has no TLS configured
	// — mirrors the NixOS evaluation-time warning. Unix socket falls
	// through (kernel mediates access via mode bits).
	if !strings.HasPrefix(hubbleAddr, "unix:") && hubbleTlsCert == "" {
		log.Warn("hubble observer on TCP without TLS — every flow event is broadcast in cleartext to anyone who can connect",
			"addr", hubbleAddr,
			"hint", "set -hubble-tls-cert and -hubble-tls-key, ideally with -hubble-tls-client-ca + -hubble-tls-require-client for mTLS")
	}
	go func() {
		if err := srv.Serve(obsCtx, hubbleAddr, hubbleTls); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Error("hubble server failed", "err", err)
		}
	}()
	log.Info("hubble observer listening", "addr", hubbleAddr, "tls", hubbleTlsCert != "", "mtls", hubbleTlsRequireClient)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	hostname, _ := os.Hostname()
	idfn := func(cgid uint64) (uint32, []string, string) {
		unit := cache.lookup(cgid)
		return observer.CgroupIdentity(cgid), observer.FormatLabels(unit, cgid), unit
	}

	go drainEvents(l.Events(), jsonLog, log, srv, hostname, idfn, cache)

	<-stop
	if stopSync != nil {
		close(stopSync)
	}
	obsCancel()
	log.Info("shutdown")
}

func drainEvents(r *ringbuf.Reader, jsonOut bool, log *slog.Logger,
	srv *observer.Server, hostname string, idfn observer.IdentityFn,
	cache *unitCache) {
	enc := json.NewEncoder(os.Stdout)
	for {
		rec, err := r.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Warn("ringbuf read", "err", err)
			continue
		}

		var raw observer.RawEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			log.Warn("decode event", "err", err)
			continue
		}

		// Publish to Hubble observer first — UI is the primary consumer.
		srv.Publish(observer.ToFlow(raw, hostname, idfn))

		if !jsonOut {
			continue
		}
		ev := flowEvent{
			TsNs:      raw.TsNs,
			CgroupID:  raw.CgroupID,
			Unit:      cache.lookup(raw.CgroupID),
			Family:    raw.Family,
			SrcIP:     ipString(raw.SrcIP[:], raw.Family),
			DstIP:     ipString(raw.DstIP[:], raw.Family),
			SrcPort:   swap16(raw.SrcPort),
			DstPort:   swap16(raw.DstPort),
			Protocol:  raw.Protocol,
			Direction: directionName(raw.Direction),
			Verdict:   verdictName(raw.Verdict),
			PolicyID:  raw.PolicyID,
		}
		_ = enc.Encode(ev)
	}
}

func swap16(v uint16) uint16 { return (v&0xff)<<8 | (v&0xff00)>>8 }

func directionName(d uint8) string {
	switch d {
	case 0:
		return "egress"
	case 1:
		return "ingress"
	default:
		return "unknown"
	}
}

func verdictName(v uint8) string {
	switch v {
	case 0:
		return "allow"
	case 1:
		return "drop"
	case 2:
		return "log"
	default:
		return "unknown"
	}
}

func verdictFromName(s string) uint8 {
	switch s {
	case "drop":
		return 1
	case "log":
		return 2
	default:
		return 0
	}
}

func boolToU8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// parseTlsPorts splits a comma-separated list like "443,8443,4443"
// into a []uint16 with strict bounds: each port must fit a uint16 and
// the total count must not exceed MAX_TLS_PORTS in microseg.c (8).
func parseTlsPorts(raw string) ([]uint16, error) {
	const max = 8
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > max {
		return nil, fmt.Errorf("at most %d TLS ports allowed, got %d", max, len(parts))
	}
	out := make([]uint16, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("port %q: %w", p, err)
		}
		if v == 0 {
			return nil, fmt.Errorf("port 0 is invalid")
		}
		out = append(out, uint16(v))
	}
	return out, nil
}
