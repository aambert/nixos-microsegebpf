// SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
// SPDX-License-Identifier: MIT

package policy

import (
	"context"
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
	// enforce=false demotes every action="drop" rule to action="log"
	// at expansion time. The eBPF program then emits a flow event but
	// returns SK_PASS, so the operator can observe what *would* have
	// been dropped without breaking the workstation. Defaults to true
	// when constructed via NewSyncer; toggle via SetEnforce.
	enforce bool
}

func NewSyncer(maps Maps, log *slog.Logger) *Syncer {
	return &Syncer{maps: maps, log: log, enforce: true}
}

// SetEnforce toggles enforcement of drop verdicts at policy
// expansion time. Call before Apply() to take effect on the next
// reconciliation. Safe to call concurrently — guarded by the same
// mutex Apply uses.
func (s *Syncer) SetEnforce(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enforce = on
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
			ev4, ev6, err := expandRules(cg.ID, d.Spec.Egress, policyID, d.Metadata.Name, s.enforce)
			if err != nil {
				return err
			}
			iv4, iv6, err := expandRules(cg.ID, d.Spec.Ingress, policyID, d.Metadata.Name, s.enforce)
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

	// Build the desired-state maps once. Duplicate keys collapse —
	// last writer wins, which matches the semantics the kernel LPM
	// trie would also enforce (single value per key).
	desiredEgV4 := entriesToMapV4(egV4)
	desiredInV4 := entriesToMapV4(inV4)
	desiredEgV6 := entriesToMapV6(egV6)
	desiredInV6 := entriesToMapV6(inV6)

	// TLS peek deny maps:
	//   * SNI: LPM trie keyed on reversed hostname, supports wildcards
	//   * ALPN: HASH on FNV-1a 64-bit (must match bpf/microseg.c::fnv64a)
	// Per-cgroup scoping is deliberately absent for the PoC — see
	// TlsSpec for the rationale.
	desiredSni := map[sniLpmEntry]rawValue{}
	desiredAlpn := map[uint64]rawValue{}
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
			desiredSni[e] = rawValue{Verdict: 1, PolicyID: pid}
		}
		for _, a := range d.Spec.Tls.ALPNDeny {
			desiredAlpn[fnv64a([]byte(a))] = rawValue{Verdict: 1, PolicyID: pid}
		}
	}

	// Delta apply, in this order:
	//   1. Adds + updates first  -> the new state lands in the BPF
	//      maps before any old entry is removed, so flows that match
	//      both old and new policy never see a transient miss.
	//   2. Deletes last           -> entries that the new policy no
	//      longer wants are removed only after every other change is
	//      already in place.
	//   3. Unchanged entries are not touched at all (no syscall).
	// This is the "no coupure" guarantee — only entries whose value
	// actually changes go through a brief atomic Update; everything
	// else stays put.
	stats := struct {
		egV4, inV4, egV6, inV6, sni, alpn deltaStats
	}{}
	var derr error
	if stats.egV4, derr = applyDelta[rawV4Key](s.maps.EgressV4, desiredEgV4, "egress_v4"); derr != nil {
		return derr
	}
	if stats.inV4, derr = applyDelta[rawV4Key](s.maps.IngressV4, desiredInV4, "ingress_v4"); derr != nil {
		return derr
	}
	if stats.egV6, derr = applyDelta[rawV6Key](s.maps.EgressV6, desiredEgV6, "egress_v6"); derr != nil {
		return derr
	}
	if stats.inV6, derr = applyDelta[rawV6Key](s.maps.IngressV6, desiredInV6, "ingress_v6"); derr != nil {
		return derr
	}
	if stats.sni, derr = applyDelta[sniLpmEntry](s.maps.TlsSniLpm, desiredSni, "tls_sni_lpm"); derr != nil {
		return derr
	}
	if stats.alpn, derr = applyDelta[uint64](s.maps.TlsAlpnDeny, desiredAlpn, "tls_alpn_deny"); derr != nil {
		return derr
	}

	s.log.Info("policy applied (delta)",
		"docs", len(docs),
		"egress_v4", stats.egV4.Compact(),
		"ingress_v4", stats.inV4.Compact(),
		"egress_v6", stats.egV6.Compact(),
		"ingress_v6", stats.inV6.Compact(),
		"tls_sni", stats.sni.Compact(),
		"tls_alpn", stats.alpn.Compact(),
	)
	return nil
}

// deltaStats summarises one map's delta-apply round.
type deltaStats struct {
	Added, Updated, Deleted, Unchanged int
}

// Compact renders the stats as a one-line summary suitable for slog
// — "+2 ~1 -3 =14" reads at a glance: 2 additions, 1 update, 3
// deletions, 14 entries left untouched.
func (s deltaStats) Compact() string {
	return fmt.Sprintf("+%d ~%d -%d =%d", s.Added, s.Updated, s.Deleted, s.Unchanged)
}

func entriesToMapV4(es []entryV4) map[rawV4Key]rawValue {
	m := make(map[rawV4Key]rawValue, len(es))
	for _, e := range es {
		m[e.key] = e.val
	}
	return m
}

func entriesToMapV6(es []entryV6) map[rawV6Key]rawValue {
	m := make(map[rawV6Key]rawValue, len(es))
	for _, e := range es {
		m[e.key] = e.val
	}
	return m
}

// applyDelta reconciles the contents of `m` with `desired`:
//
//   - keys present in `desired` whose current value matches:   no-op
//   - keys present in `desired` whose current value differs:   Update (atomic at kernel level)
//   - keys present in `desired` but absent from the map:       Update (insert)
//   - keys present in the map but absent from `desired`:       Delete
//
// Adds + updates are applied before deletes so there is no transient
// state where the new policy is missing an entry it should have.
//
// `K` must be the exact Go shape of the BPF map's key type — it's
// passed to `bpf_map_lookup_elem` / `bpf_map_update_elem` as raw
// bytes, so any padding mismatch silently breaks the contract.
func applyDelta[K comparable](m *ebpf.Map, desired map[K]rawValue, label string) (deltaStats, error) {
	var stats deltaStats
	if m == nil {
		return stats, nil
	}

	current := map[K]rawValue{}
	var k K
	var v rawValue
	it := m.Iterate()
	for it.Next(&k, &v) {
		current[k] = v
	}

	for desKey, desVal := range desired {
		cur, exists := current[desKey]
		if exists && cur == desVal {
			stats.Unchanged++
			continue
		}
		kk, vv := desKey, desVal
		if err := m.Update(&kk, &vv, ebpf.UpdateAny); err != nil {
			return stats, fmt.Errorf("%s update: %w", label, err)
		}
		if exists {
			stats.Updated++
		} else {
			stats.Added++
		}
	}

	for curKey := range current {
		if _, exists := desired[curKey]; exists {
			continue
		}
		kk := curKey
		if err := m.Delete(&kk); err != nil {
			return stats, fmt.Errorf("%s delete: %w", label, err)
		}
		stats.Deleted++
	}
	return stats, nil
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

func expandRules(cgroupID uint64, rules []Rule, policyID uint32, name string, enforce bool) ([]entryV4, []entryV6, error) {
	var v4 []entryV4
	var v6 []entryV6

	for _, r := range rules {
		// Each rule yields one or more (CIDR, family) pairs. A `cidr`
		// rule produces exactly one; a `host` rule produces one per
		// resolved A/AAAA record.
		nets, err := resolveRuleTargets(r)
		if err != nil {
			return nil, nil, fmt.Errorf("policy %q: %w", name, err)
		}

		for _, ipnet := range nets {
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

			// enforce=false demotes drops to logs at expansion time so
			// the kernel datapath never returns SK_DROP. The flow event
			// is still emitted with the matched policy id, so Hubble
			// (and the OpenSearch log shipper) can show what *would*
			// have been dropped — useful during the bake-in phase
			// before flipping enforcement on.
			action := r.Action
			if !enforce && action == "drop" {
				action = "log"
			}
			val := rawValue{Verdict: VerdictCode(action), PolicyID: policyID}

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

			// "Any port" sentinel: re-tune the prefix_len of the entries
			// we just appended so the LPM lookup ignores the port field.
			// Done per ipnet because each FQDN-resolved address may have
			// a different family / prefix length.
			if len(r.Ports) == 0 {
				adjustPrefixForAnyPort(&v4, &v6, ones, bits)
			}
		}
	}
	return v4, v6, nil
}

// resolveRuleTargets returns the list of CIDR/IP targets the rule
// applies to. For a CIDR-shaped rule it's a single entry; for a
// Host-shaped rule it's one entry per resolved A/AAAA record (each
// as a /32 or /128). DNS lookup uses the system resolver with a 2-
// second timeout so a slow / failing resolver doesn't stall the
// agent's Apply loop.
func resolveRuleTargets(r Rule) ([]*net.IPNet, error) {
	if r.CIDR != "" {
		_, n, err := net.ParseCIDR(r.CIDR)
		if err != nil {
			return nil, fmt.Errorf("cidr %q: %w", r.CIDR, err)
		}
		return []*net.IPNet{n}, nil
	}
	if r.Host == "" {
		return nil, fmt.Errorf("rule has neither cidr nor host")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, r.Host)
	if err != nil {
		return nil, fmt.Errorf("host %q: resolve: %w", r.Host, err)
	}
	out := make([]*net.IPNet, 0, len(addrs))
	for _, a := range addrs {
		if v4 := a.IP.To4(); v4 != nil {
			out = append(out, &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)})
		} else {
			out = append(out, &net.IPNet{IP: a.IP.To16(), Mask: net.CIDRMask(128, 128)})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("host %q: resolved to no addresses", r.Host)
	}
	return out, nil
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
