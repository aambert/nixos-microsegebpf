// SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
// SPDX-License-Identifier: MIT

// Package policy parses workstation microsegmentation policies and reduces
// them to LPM_TRIE entries (per address family, per direction) for the
// eBPF datapath.
//
// Capabilities:
//   - IPv4 and IPv6 CIDR (any prefix length)
//   - Single port or port range (`80-89`); empty list means "any port"
//   - Selector by systemd unit (glob) or cgroup path prefix
//
// Sanity limit: a single rule that expands to more than `maxExpansion`
// (cgroup × port × proto) entries is rejected at parse time. This
// catches "block 0.0.0.0/0 ports 1-65535 udp+tcp" mistakes that would
// otherwise blow up the BPF map.
package policy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxExpansion = 16384

type PolicyDoc struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

type Metadata struct {
	Name string `yaml:"name"`
}

type Spec struct {
	Selector Selector `yaml:"selector"`
	Egress   []Rule   `yaml:"egress"`
	Ingress  []Rule   `yaml:"ingress"`
	// Tls holds peek-only deny lists for TLS handshake metadata. The
	// agent merges sniDeny / alpnDeny from every policy into two
	// global BPF maps; per-cgroup scoping is intentionally absent in
	// the PoC because the in-kernel parser keys the lookup on the
	// hash alone. The selector at the surrounding policy doc is
	// documentary in this case.
	Tls *TlsSpec `yaml:"tls,omitempty"`
}

// TlsSpec lists hostnames (SNI) and ALPN protocol identifiers that
// should be dropped at the kernel boundary when seen in cleartext in
// a TLS ClientHello. Matching is byte-exact and case-sensitive — the
// SNI host_name field is already lowercased by every common client.
type TlsSpec struct {
	SNIDeny  []string `yaml:"sniDeny"`
	ALPNDeny []string `yaml:"alpnDeny"`
}

type Selector struct {
	SystemdUnit string `yaml:"systemdUnit"`
	CgroupPath  string `yaml:"cgroupPath"`
}

// Rule is one allow/drop entry.
//
// Exactly one of `CIDR` or `Host` must be set:
//   - CIDR ("10.0.0.0/24", "1.1.1.1/32", "2001:4860::/32") — the
//     IP / prefix is matched directly in the kernel LPM trie.
//   - Host ("internal-api.corp.example.com") — the agent resolves
//     the FQDN to A and AAAA records via the system resolver and
//     installs one /32 (v4) or /128 (v6) entry per resolved address.
//     Re-resolution happens on every Apply() (cgroup-event-driven
//     or fallback ticker), so the rule follows the FQDN as its DNS
//     records change. A resolution failure logs a warning and skips
//     the rule for that Apply round.
//
// Ports may be a single number ("443") or a range ("8000-8099"). An
// empty Ports list matches every L4 port for the chosen protocol.
type Rule struct {
	Action   string   `yaml:"action"`
	CIDR     string   `yaml:"cidr"`
	Host     string   `yaml:"host"`
	Ports    []string `yaml:"ports"`
	Protocol string   `yaml:"protocol"` // tcp | udp | "" (= both)
}

// MaxPolicyFileBytes caps the size of a policy file the agent will
// parse. Policy bundles in practice top out at a few hundred KB even
// with large threat-feed expansions (see ports/IP combinatorics in
// pkg/policy/sync.go::expandRules where maxExpansion = 16384 per
// rule already constrains downstream growth). The cap is a defence
// against a billion-laughs / nested-anchor YAML attack — see
// SECURITY-AUDIT.md §F-2. Bump consciously if your bundle truly
// requires more.
const MaxPolicyFileBytes = 16 * 1024 * 1024

func LoadFile(path string) ([]PolicyDoc, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read up to cap+1 so we can detect overrun explicitly: a silent
	// truncation by io.LimitReader would parse a partial file and the
	// agent would happily install zero policies, which is the worst
	// possible failure mode for a security control.
	buf, err := io.ReadAll(io.LimitReader(f, MaxPolicyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("policy read: %w", err)
	}
	if int64(len(buf)) > MaxPolicyFileBytes {
		return nil, fmt.Errorf("policy file %q exceeds cap of %d bytes (set MaxPolicyFileBytes higher only if your bundle truly requires it)", path, MaxPolicyFileBytes)
	}

	dec := yaml.NewDecoder(bytes.NewReader(buf))
	var docs []PolicyDoc
	for {
		var d PolicyDoc
		if err := dec.Decode(&d); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("policy decode: %w", err)
		}
		if d.Kind == "" {
			continue
		}
		if err := d.validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", d.Metadata.Name, err)
		}
		docs = append(docs, d)
	}
	return docs, nil
}

func (d *PolicyDoc) validate() error {
	if d.Kind != "Policy" {
		return fmt.Errorf("unsupported kind %q", d.Kind)
	}
	if d.Metadata.Name == "" {
		return fmt.Errorf("metadata.name required")
	}
	if d.Spec.Selector.SystemdUnit == "" && d.Spec.Selector.CgroupPath == "" {
		return fmt.Errorf("selector requires systemdUnit or cgroupPath")
	}
	for i, r := range d.Spec.Egress {
		if err := r.validate(); err != nil {
			return fmt.Errorf("egress[%d]: %w", i, err)
		}
	}
	for i, r := range d.Spec.Ingress {
		if err := r.validate(); err != nil {
			return fmt.Errorf("ingress[%d]: %w", i, err)
		}
	}
	if d.Spec.Tls != nil {
		for i, s := range d.Spec.Tls.SNIDeny {
			if s == "" || len(s) > 255 {
				return fmt.Errorf("tls.sniDeny[%d]: empty or > 255 bytes", i)
			}
		}
		for i, a := range d.Spec.Tls.ALPNDeny {
			if a == "" || len(a) > 255 {
				return fmt.Errorf("tls.alpnDeny[%d]: empty or > 255 bytes", i)
			}
		}
	}
	return nil
}

func (r *Rule) validate() error {
	switch r.Action {
	case "allow", "drop", "log":
	default:
		return fmt.Errorf("action must be allow|drop|log, got %q", r.Action)
	}
	hasCIDR := r.CIDR != ""
	hasHost := r.Host != ""
	if hasCIDR == hasHost {
		return fmt.Errorf("exactly one of cidr or host must be set")
	}
	if hasCIDR {
		if _, _, err := net.ParseCIDR(r.CIDR); err != nil {
			return fmt.Errorf("cidr %q: %w", r.CIDR, err)
		}
	} else {
		if len(r.Host) > 253 {
			return fmt.Errorf("host %q exceeds DNS max length 253", r.Host)
		}
		if strings.ContainsAny(r.Host, " \t/") {
			return fmt.Errorf("host %q must be a bare DNS name", r.Host)
		}
	}
	if r.Protocol != "" && r.Protocol != "tcp" && r.Protocol != "udp" {
		return fmt.Errorf("protocol must be tcp|udp|empty, got %q", r.Protocol)
	}
	for _, p := range r.Ports {
		if _, _, err := parsePortSpec(p); err != nil {
			return fmt.Errorf("ports[%q]: %w", p, err)
		}
	}
	return nil
}

// parsePortSpec accepts "443" or "8000-8099" (inclusive).
func parsePortSpec(s string) (lo, hi uint16, err error) {
	if s == "" {
		return 0, 0, fmt.Errorf("empty port spec")
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		var l, h int
		_, err = fmt.Sscanf(s[:i], "%d", &l)
		if err != nil {
			return 0, 0, fmt.Errorf("low port: %w", err)
		}
		_, err = fmt.Sscanf(s[i+1:], "%d", &h)
		if err != nil {
			return 0, 0, fmt.Errorf("high port: %w", err)
		}
		if l < 1 || h > 65535 || l > h {
			return 0, 0, fmt.Errorf("invalid range %d-%d", l, h)
		}
		return uint16(l), uint16(h), nil
	}
	var p int
	_, err = fmt.Sscanf(s, "%d", &p)
	if err != nil {
		return 0, 0, err
	}
	if p < 1 || p > 65535 {
		return 0, 0, fmt.Errorf("port out of range")
	}
	return uint16(p), uint16(p), nil
}

func VerdictCode(s string) uint8 {
	switch s {
	case "drop":
		return 1
	case "log":
		return 2
	default:
		return 0
	}
}

func ProtocolCodes(s string) []uint8 {
	switch strings.ToLower(s) {
	case "tcp":
		return []uint8{6}
	case "udp":
		return []uint8{17}
	default:
		return []uint8{6, 17}
	}
}
