// SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
// SPDX-License-Identifier: MIT

package observer

import (
	"net"
	"strings"
	"sync"
	"time"
)

// NameFn returns the reverse-DNS names known for an IP (may be nil).
type NameFn func(ip string) []string

// NameResolver does cached, non-blocking reverse-DNS (PTR) on peer IPs so the
// Hubble flow can carry destination/source hostnames instead of raw IPs. A
// cache miss returns nil immediately AND schedules a background lookup; the
// next flow to the same IP gets the cached names. It never blocks the datapath
// goroutine — the eBPF ring consumer must never wait on the network resolver.
type NameResolver struct {
	mu       sync.Mutex
	cache    map[string]nameEntry
	inflight map[string]struct{}
	ttl      time.Duration
}

type nameEntry struct {
	names []string
	exp   time.Time
}

// NewNameResolver builds a resolver with the given cache TTL (defaults to 5m
// when ttl <= 0).
func NewNameResolver(ttl time.Duration) *NameResolver {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &NameResolver{
		cache:    map[string]nameEntry{},
		inflight: map[string]struct{}{},
		ttl:      ttl,
	}
}

// Names returns cached reverse-DNS names for ip, or nil on a miss (scheduling a
// background lookup). Trailing dots are trimmed. Safe for concurrent use.
func (r *NameResolver) Names(ip string) []string {
	if ip == "" {
		return nil
	}
	r.mu.Lock()
	if e, ok := r.cache[ip]; ok && time.Now().Before(e.exp) {
		r.mu.Unlock()
		return e.names
	}
	if _, busy := r.inflight[ip]; !busy {
		r.inflight[ip] = struct{}{}
		go r.lookup(ip)
	}
	r.mu.Unlock()
	return nil
}

func (r *NameResolver) lookup(ip string) {
	names, _ := net.LookupAddr(ip)
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n = strings.TrimSuffix(n, "."); n != "" {
			out = append(out, n)
		}
	}
	r.mu.Lock()
	r.cache[ip] = nameEntry{names: out, exp: time.Now().Add(r.ttl)}
	delete(r.inflight, ip)
	r.mu.Unlock()
}
