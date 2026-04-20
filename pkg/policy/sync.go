// SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
// SPDX-License-Identifier: MIT

package policy

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"

	"github.com/aambert/nixos-microsegebpf/pkg/identity"
)

// policyHeaderBits mirrors POLICY_HEADER_BITS in microseg.c. Changing
// either side requires the other to follow.
const policyHeaderBits = 88 // cgroup_id(64) + peer_port(16) + protocol(8)

// Maps groups the BPF maps the syncer owns. Four LPM tries for
// (direction × family), one LPM trie on reversed SNI hostnames (for
// wildcard matching), and one HASH map for ALPN identifiers.
type Maps struct {
	EgressV4    *ebpf.Map
	IngressV4   *ebpf.Map
	EgressV6    *ebpf.Map
	IngressV6   *ebpf.Map
	TlsSniLpm   *ebpf.Map
	TlsAlpnDeny *ebpf.Map
}

type Syncer struct {
	maps Maps
	log  *slog.Logger
	mu   sync.Mutex
}

func NewSyncer(maps Maps, log *slog.Logger) *Syncer {
	return &Syncer{maps: maps, log: log}
}

// Wire layout mirrors struct lpm_v4_key / lpm_v6_key in microseg.c.
// Packed to match the C side; the BPF map operates on raw bytes.
type rawV4Key struct {
	PrefixLen uint32
	CgroupID  uint64
	PeerPort  uint16
	Protocol  uint8
	IP        [4]byte
}

type rawV6Key struct {
	PrefixLen uint32
	CgroupID  uint64
	PeerPort  uint16
	Protocol  uint8
	IP        [16]byte
}

type rawValue struct {
	Verdict  uint8
	Pad      [3]uint8
	PolicyID uint32
}

type entryV4 struct {
	key rawV4Key
	val rawValue
}
type entryV6 struct {
	key rawV6Key
	val rawValue
}

func (s *Syncer) Apply(docs []PolicyDoc) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cgs, err := identity.Snapshot()
	if err != nil {
		return fmt.Errorf("cgroup snapshot: %w", err)
	}

	var egV4, inV4 []entryV4
	var egV6, inV6 []entryV6

	policyID := uint32(1)
	for _, d := range docs {
		matches := selectCgroups(d.Spec.Selector, cgs)
		if len(matches) == 0 {
			s.log.Info("policy without matching cgroup",
				"policy", d.Metadata.Name,
				"unit", d.Spec.Selector.SystemdUnit,
				"path", d.Spec.Selector.CgroupPath)
		}
		for _, cg := range matches {
			ev4, ev6, err := expandRules(cg.ID, d.Spec.Egress, policyID, d.Metadata.Name)
			if err != nil {
				return err
			}
			iv4, iv6, err := expandRules(cg.ID, d.Spec.Ingress, policyID, d.Metadata.Name)
			if err != nil {
				return err
			}
			egV4 = append(egV4, ev4...)
			egV6 = append(egV6, ev6...)
			inV4 = append(inV4, iv4...)
			inV6 = append(inV6, iv6...)
		}
		policyID++
	}

	if err := replaceV4(s.maps.EgressV4, egV4, "egress_v4"); err != nil {
		return err
	}
	if err := replaceV4(s.maps.IngressV4, inV4, "ingress_v4"); err != nil {
		return err
	}
	if err := replaceV6(s.maps.EgressV6, egV6, "egress_v6"); err != nil {
		return err
	}
	if err := replaceV6(s.maps.IngressV6, inV6, "ingress_v6"); err != nil {
		return err
	}

	// TLS peek deny maps:
	//   * SNI: LPM trie keyed on reversed hostname, supports wildcards
	//   * ALPN: HASH on FNV-1a 64-bit (must match bpf/microseg.c::fnv64a)
	// Per-cgroup scoping is deliberately absent for the PoC — see
	// TlsSpec for the rationale.
	sniEntries := map[sniLpmEntry]uint32{}
	alpnHashes := map[uint64]uint32{}
	for i, d := range docs {
		if d.Spec.Tls == nil {
			continue
		}
		pid := uint32(i + 1)
		for _, pat := range d.Spec.Tls.SNIDeny {
			e, err := compileSNIPattern(pat)
			if err != nil {
				return fmt.Errorf("policy %q: tls.sniDeny[%q]: %w", d.Metadata.Name, pat, err)
			}
			sniEntries[e] = pid
		}
		for _, a := range d.Spec.Tls.ALPNDeny {
			alpnHashes[fnv64a([]byte(a))] = pid
		}
	}
	if err := replaceSniLpm(s.maps.TlsSniLpm, sniEntries, "tls_sni_lpm"); err != nil {
		return err
	}
	if err := replaceTlsHash(s.maps.TlsAlpnDeny, alpnHashes, "tls_alpn_deny"); err != nil {
		return err
	}

	s.log.Info("policy applied",
		"docs", len(docs),
		"egress_v4", len(egV4), "ingress_v4", len(inV4),
		"egress_v6", len(egV6), "ingress_v6", len(inV6),
		"tls_sni", len(sniEntries), "tls_alpn", len(alpnHashes),
	)
	return nil
}

// sniLpmEntry is the raw (prefix_len, name[256]) shape of a single
// LPM trie entry. Used as a map key in Apply() so we can dedupe
// patterns that compile to the same key.
type sniLpmEntry struct {
	PrefixLen uint32
	Name      [256]byte
}

// compileSNIPattern turns a userspace SNI pattern into the BPF LPM
// key the in-kernel parser will look up. Two flavours:
//
//   "example.com"      -> reversed bytes + NUL terminator. The NUL
//                         prevents a longer reversed lookup string
//                         from matching this entry (otherwise an
//                         exact-match for example.com would also
//                         match mail.example.com).
//   "*.example.com"    -> reversed bytes (without the leading "*.")
//                         + dot terminator. The trailing dot ensures
//                         a label boundary in the original-direction
//                         hostname, so "evilexample.com" does NOT
//                         match.
//
// Multi-level wildcards (e.g. "*.*.foo.com") are explicitly rejected
// because they have no standard meaning in DNS / TLS SNI and the LPM
// design only models one wildcard label.
func compileSNIPattern(pat string) (sniLpmEntry, error) {
	pat = strings.ToLower(strings.TrimSpace(pat))
	if pat == "" {
		return sniLpmEntry{}, fmt.Errorf("empty pattern")
	}
	if strings.Count(pat, "*") > 1 {
		return sniLpmEntry{}, fmt.Errorf("multi-level wildcards are not supported")
	}

	var raw []byte
	if strings.HasPrefix(pat, "*.") {
		// Wildcard subdomain. Strip the leading "*", keep the dot.
		rest := pat[1:] // ".example.com"
		if strings.Contains(rest[1:], "*") {
			return sniLpmEntry{}, fmt.Errorf("'*' allowed only as leftmost label")
		}
		raw = []byte(reverseBytes(rest))
	} else {
		if strings.Contains(pat, "*") {
			return sniLpmEntry{}, fmt.Errorf("'*' allowed only as leftmost label (use '*.foo.com')")
		}
		// Exact pattern. Append NUL so a longer lookup doesn't match.
		raw = append([]byte(reverseBytes(pat)), 0)
	}
	if len(raw) > 256 {
		return sniLpmEntry{}, fmt.Errorf("pattern too long after reversal (%d > 256)", len(raw))
	}

	var e sniLpmEntry
	e.PrefixLen = uint32(len(raw)) * 8
	copy(e.Name[:], raw)
	return e, nil
}

func reverseBytes(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

// replaceSniLpm flushes and repopulates the SNI LPM trie. Same
// pattern as the v4/v6 LPM replace functions.
func replaceSniLpm(m *ebpf.Map, entries map[sniLpmEntry]uint32, label string) error {
	if m == nil {
		return nil
	}
	var k sniLpmEntry
	var v rawValue
	it := m.Iterate()
	var keys []sniLpmEntry
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for i := range keys {
		_ = m.Delete(&keys[i])
	}
	for k, pid := range entries {
		hk := k
		val := rawValue{Verdict: 1, PolicyID: pid}
		if err := m.Update(&hk, &val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("%s update: %w", label, err)
		}
	}
	return nil
}

// fnv64a is the byte-for-byte twin of bpf/microseg.c::fnv64a. Drift
// here means TLS lookups silently miss; keep them in lockstep.
func fnv64a(b []byte) uint64 {
	const offset = 0xcbf29ce484222325
	const prime = 0x100000001b3
	h := uint64(offset)
	for _, c := range b {
		h ^= uint64(c)
		h *= prime
	}
	return h
}

// replaceTlsHash flushes and repopulates a u64 -> rawValue HASH map.
// Used for tls_alpn_deny (and historically tls_sni_deny before the SNI
// map became LPM-keyed in tls_sni_lpm). They share the same
// shape.
func replaceTlsHash(m *ebpf.Map, entries map[uint64]uint32, label string) error {
	if m == nil {
		return nil
	}
	var k uint64
	var v rawValue
	it := m.Iterate()
	var keys []uint64
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for i := range keys {
		_ = m.Delete(&keys[i])
	}
	for h, pid := range entries {
		hk := h
		val := rawValue{Verdict: 1, PolicyID: pid}
		if err := m.Update(&hk, &val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("%s update: %w", label, err)
		}
	}
	return nil
}

func selectCgroups(sel Selector, cgs []identity.Cgroup) []identity.Cgroup {
	var out []identity.Cgroup
	for _, cg := range cgs {
		switch {
		case sel.SystemdUnit != "" && identity.MatchUnitGlob(sel.SystemdUnit, cg.SystemdUnit):
			out = append(out, cg)
		case sel.CgroupPath != "" && identity.MatchPathPrefix(sel.CgroupPath, cg.Path):
			out = append(out, cg)
		}
	}
	return out
}

func expandRules(cgroupID uint64, rules []Rule, policyID uint32, name string) ([]entryV4, []entryV6, error) {
	var v4 []entryV4
	var v6 []entryV6

	for _, r := range rules {
		_, ipnet, err := net.ParseCIDR(r.CIDR)
		if err != nil {
			return nil, nil, fmt.Errorf("policy %q: cidr %q: %w", name, r.CIDR, err)
		}
		ones, bits := ipnet.Mask.Size()

		// Build the port set: each spec is a single port or a closed
		// range. An empty port list matches every L4 port for the
		// selected protocol.
		var ports []uint16
		if len(r.Ports) == 0 {
			ports = []uint16{0} // sentinel: 0 means "any port"
		} else {
			for _, ps := range r.Ports {
				lo, hi, err := parsePortSpec(ps)
				if err != nil {
					return nil, nil, fmt.Errorf("policy %q: %w", name, err)
				}
				for p := uint32(lo); p <= uint32(hi); p++ {
					ports = append(ports, uint16(p))
				}
			}
		}

		protos := ProtocolCodes(r.Protocol)
		count := len(ports) * len(protos)
		if count > maxExpansion {
			return nil, nil, fmt.Errorf("policy %q: rule expands to %d entries (limit %d)", name, count, maxExpansion)
		}

		val := rawValue{Verdict: VerdictCode(r.Action), PolicyID: policyID}

		switch bits {
		case 32:
			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				return nil, nil, fmt.Errorf("policy %q: cidr %q: not IPv4", name, r.CIDR)
			}
			for _, p := range ports {
				portBE := uint16ToBE(p)
				if p == 0 {
					portBE = 0
				}
				for _, proto := range protos {
					k := rawV4Key{
						PrefixLen: uint32(policyHeaderBits + ones),
						CgroupID:  cgroupID,
						PeerPort:  portBE,
						Protocol:  proto,
					}
					copy(k.IP[:], ip4)
					v4 = append(v4, entryV4{key: k, val: val})
				}
			}
		case 128:
			ip6 := ipnet.IP.To16()
			for _, p := range ports {
				portBE := uint16ToBE(p)
				if p == 0 {
					portBE = 0
				}
				for _, proto := range protos {
					k := rawV6Key{
						PrefixLen: uint32(policyHeaderBits + ones),
						CgroupID:  cgroupID,
						PeerPort:  portBE,
						Protocol:  proto,
					}
					copy(k.IP[:], ip6)
					v6 = append(v6, entryV6{key: k, val: val})
				}
			}
		default:
			return nil, nil, fmt.Errorf("policy %q: cidr %q has unsupported address size %d", name, r.CIDR, bits)
		}

		// "Any port" means we also need entries with prefix excluding
		// the port byte from exact match. Cleaner implementation: when
		// ports is the {0} sentinel, set prefix_len to skip the port
		// field entirely (cgroup_id 64 + 0 + proto 8 + ip = 72 + ip).
		// Re-emit with corrected prefix_len.
		if len(r.Ports) == 0 {
			// Drop what we just appended for port=0 and re-add with
			// prefix_len adjusted to ignore the port field.
			adjustPrefixForAnyPort(&v4, &v6, ones, bits)
		}
	}
	return v4, v6, nil
}

// adjustPrefixForAnyPort shrinks prefix_len so the LPM lookup does not
// try to match the (already-zero) port bytes. Called only for entries
// emitted by the "any port" path.
func adjustPrefixForAnyPort(v4 *[]entryV4, v6 *[]entryV6, cidrOnes, bits int) {
	const cgroupBits = 64
	const portBits = 16
	const protoBits = 8
	const wildcardHeader = cgroupBits + protoBits // skip port

	if bits == 32 {
		for i := len(*v4) - 1; i >= 0; i-- {
			if (*v4)[i].key.PeerPort == 0 {
				(*v4)[i].key.PrefixLen = uint32(wildcardHeader + cidrOnes)
			} else {
				break
			}
		}
		_ = portBits
	} else if bits == 128 {
		for i := len(*v6) - 1; i >= 0; i-- {
			if (*v6)[i].key.PeerPort == 0 {
				(*v6)[i].key.PrefixLen = uint32(wildcardHeader + cidrOnes)
			} else {
				break
			}
		}
	}
}

func uint16ToBE(v uint16) uint16 {
	return (v&0xff)<<8 | (v&0xff00)>>8
}

// flushV4 / flushV6 drain a map by collecting every key then deleting
// them. PoC trades a tiny atomicity gap for code simplicity; a delta
// update is on the production roadmap.
func flushV4(m *ebpf.Map) {
	var k rawV4Key
	var v rawValue
	it := m.Iterate()
	var keys []rawV4Key
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for i := range keys {
		_ = m.Delete(&keys[i])
	}
}

func flushV6(m *ebpf.Map) {
	var k rawV6Key
	var v rawValue
	it := m.Iterate()
	var keys []rawV6Key
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	for i := range keys {
		_ = m.Delete(&keys[i])
	}
}

func replaceV4(m *ebpf.Map, entries []entryV4, label string) error {
	flushV4(m)
	for i := range entries {
		if err := m.Update(&entries[i].key, &entries[i].val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("%s update: %w", label, err)
		}
	}
	return nil
}

func replaceV6(m *ebpf.Map, entries []entryV6, label string) error {
	flushV6(m)
	for i := range entries {
		if err := m.Update(&entries[i].key, &entries[i].val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("%s update: %w", label, err)
		}
	}
	return nil
}

// Resolve runs Apply whenever `events` fires (event-driven, typically
// from inotify) and again on a slow safety-net ticker (`fallback`).
// Returns a stop channel; close it to terminate the goroutine.
//
// Pass a nil events channel to disable event-driven updates and rely
// only on the timer.
func (s *Syncer) Resolve(docs []PolicyDoc, events <-chan struct{}, fallback time.Duration) chan<- struct{} {
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(fallback)
		defer t.Stop()
		var ch <-chan struct{} = events
		if ch == nil {
			ch = make(chan struct{}) // never fires
		}
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if err := s.Apply(docs); err != nil {
					s.log.Warn("periodic apply failed", "err", err)
				}
			case <-ch:
				if err := s.Apply(docs); err != nil {
					s.log.Warn("event-driven apply failed", "err", err)
				}
			}
		}
	}()
	return stop
}
