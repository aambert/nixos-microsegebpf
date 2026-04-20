// SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
// SPDX-License-Identifier: MIT

// Package loader wires the eBPF datapath to the host: it loads the compiled
// CO-RE object, pins the maps under /sys/fs/bpf/microseg, and attaches the
// cgroup_skb programs to the cgroupv2 root.
//
// Lifecycle: callers construct a Loader, call Load(), then Attach(). Close()
// detaches and unpins. The eBPF maps are exposed for the policy and observer
// packages to populate and read from.
package loader

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	bpfobj "github.com/aambert/nixos-microsegebpf/bpf"
)

const (
	bpfFSRoot     = "/sys/fs/bpf/microseg"
	cgroupV2Root  = "/sys/fs/cgroup"
)

// Loader owns the eBPF objects and their kernel attachments.
type Loader struct {
	objs   bpfobj.MicrosegObjects
	egress link.Link
	ingrs  link.Link
	reader *ringbuf.Reader
}

// New returns a Loader with no kernel state yet.
func New() *Loader { return &Loader{} }

// Load opens the embedded BPF object, applies CO-RE relocations against the
// running kernel's BTF, and pins the maps so cilium-style debugging tools
// (bpftool map dump pinned ...) can introspect live state.
func (l *Loader) Load() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	if err := os.MkdirAll(bpfFSRoot, 0o755); err != nil {
		return fmt.Errorf("mkdir bpffs: %w", err)
	}

	spec, err := bpfobj.LoadMicroseg()
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
	}

	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: bpfFSRoot},
	}

	if err := spec.LoadAndAssign(&l.objs, &opts); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			return fmt.Errorf("verifier rejected program:\n%+v", verr)
		}
		return fmt.Errorf("load and assign: %w", err)
	}

	return nil
}

// Attach hooks the egress and ingress programs onto the cgroupv2 root, so
// every process on the host inherits the policy unless overridden by a
// child cgroup attach.
func (l *Loader) Attach() error {
	cg, err := os.Open(cgroupV2Root)
	if err != nil {
		return fmt.Errorf("open cgroup root: %w", err)
	}
	defer cg.Close()

	l.egress, err = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupV2Root,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: l.objs.MicrosegEgress,
	})
	if err != nil {
		return fmt.Errorf("attach egress: %w", err)
	}

	l.ingrs, err = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupV2Root,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: l.objs.MicrosegIngress,
	})
	if err != nil {
		return fmt.Errorf("attach ingress: %w", err)
	}

	// Replace any stale pin from a previous (crashed or kill-9'd) run.
	// AttachCgroup already created a fresh kernel link; the leftover pin
	// only points at the previous one, which is now gone.
	pin := func(lk link.Link, name string) error {
		path := filepath.Join(bpfFSRoot, name)
		_ = os.Remove(path)
		return lk.Pin(path)
	}
	if err := pin(l.egress, "link_egress"); err != nil {
		return fmt.Errorf("pin egress link: %w", err)
	}
	if err := pin(l.ingrs, "link_ingress"); err != nil {
		return fmt.Errorf("pin ingress link: %w", err)
	}

	l.reader, err = ringbuf.NewReader(l.objs.Events)
	if err != nil {
		return fmt.Errorf("ringbuf reader: %w", err)
	}

	return nil
}

// Events returns the ringbuf reader. Callers read flow_event records.
func (l *Loader) Events() *ringbuf.Reader { return l.reader }

// Map accessors — split per address family so the policy package can
// build correctly-sized LPM keys for each.
func (l *Loader) EgressV4Map() *ebpf.Map    { return l.objs.EgressV4 }
func (l *Loader) IngressV4Map() *ebpf.Map   { return l.objs.IngressV4 }
func (l *Loader) EgressV6Map() *ebpf.Map    { return l.objs.EgressV6 }
func (l *Loader) IngressV6Map() *ebpf.Map   { return l.objs.IngressV6 }
func (l *Loader) ConfigMap() *ebpf.Map      { return l.objs.MicrosegCfg }
func (l *Loader) TlsSniLpmMap() *ebpf.Map   { return l.objs.TlsSniLpm }
func (l *Loader) TlsAlpnDenyMap() *ebpf.Map { return l.objs.TlsAlpnDeny }

// Close detaches programs, closes maps, and removes pins.
func (l *Loader) Close() error {
	var errs []error
	if l.reader != nil {
		errs = append(errs, l.reader.Close())
	}
	if l.egress != nil {
		errs = append(errs, l.egress.Close())
	}
	if l.ingrs != nil {
		errs = append(errs, l.ingrs.Close())
	}
	errs = append(errs, l.objs.Close())
	return errors.Join(errs...)
}
