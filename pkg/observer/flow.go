// SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
// SPDX-License-Identifier: MIT

package observer

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"
	"strconv"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

// RawEvent mirrors `struct flow_event` in microseg.c v2 (LPM + IPv6
// rewrite). Field order and sizing must stay in sync.
type RawEvent struct {
	TsNs      uint64
	CgroupID  uint64
	Family    uint8 // 4 or 6
	Direction uint8 // 0 egress, 1 ingress
	Verdict   uint8 // 0 allow, 1 drop, 2 log
	Protocol  uint8
	SrcPort   uint16 // network byte order
	DstPort   uint16 // network byte order
	PolicyID  uint32
	SrcIP     [16]byte
	DstIP     [16]byte
}

type IdentityFn func(cgroupID uint64) (id uint32, labels []string, unit string)

func ToFlow(e RawEvent, hostname string, idfn IdentityFn, names NameFn) *flowpb.Flow {
	srcIP, dstIP := ipString(e.SrcIP[:], e.Family), ipString(e.DstIP[:], e.Family)
	srcPort := uint32(beU16(e.SrcPort))
	dstPort := uint32(beU16(e.DstPort))

	if names == nil {
		names = func(string) []string { return nil }
	}
	id, labels, unit := idfn(e.CgroupID)

	localEP := &flowpb.Endpoint{
		ID:          id,
		Identity:    id,
		ClusterName: "host",
		Namespace:   "microseg",
		Labels:      labels,
		PodName:     localPodName(unit, e.CgroupID),
	}
	worldEP := &flowpb.Endpoint{
		Identity:    2, // RESERVED_IDENTITY_WORLD
		ClusterName: "world",
		Namespace:   "world",
		Labels:      []string{"reserved:world"},
	}

	var src, dst *flowpb.Endpoint
	var trafDir flowpb.TrafficDirection
	if e.Direction == 0 {
		src, dst = localEP, worldEP
		trafDir = flowpb.TrafficDirection_EGRESS
	} else {
		src, dst = worldEP, localEP
		trafDir = flowpb.TrafficDirection_INGRESS
	}

	// Reverse-DNS the remote peer so the world endpoint carries a hostname
	// (Hubble names the node by k8s:app; SourceNames/DestinationNames drive
	// the DNS column). Non-blocking: a miss returns nil and resolves async.
	peerIP := dstIP
	if e.Direction == 1 {
		peerIP = srcIP
	}
	if pn := names(peerIP); len(pn) > 0 {
		worldEP.Labels = append(worldEP.Labels, "k8s:app="+pn[0], "fqdn:"+pn[0])
	}

	verdict := flowpb.Verdict_FORWARDED
	switch e.Verdict {
	case 1:
		verdict = flowpb.Verdict_DROPPED
	case 2:
		verdict = flowpb.Verdict_AUDIT
	}

	ipVer := flowpb.IPVersion_IPv4
	if e.Family == 6 {
		ipVer = flowpb.IPVersion_IPv6
	}

	f := &flowpb.Flow{
		Time:    timestamppb.New(time.Now()),
		Verdict: verdict,
		IP: &flowpb.IP{
			Source:      srcIP,
			Destination: dstIP,
			IpVersion:   ipVer,
		},
		Source:           src,
		Destination:      dst,
		SourceNames:      names(srcIP),
		DestinationNames: names(dstIP),
		TrafficDirection: trafDir,
		NodeName:         hostname,
		Type:             flowpb.FlowType_L3_L4,
		EventType: &flowpb.CiliumEventType{
			Type:    1,
			SubType: int32(e.PolicyID),
		},
		IsReply: &wrapperspb.BoolValue{Value: false},
	}

	switch e.Protocol {
	case 6:
		f.L4 = &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{
			SourcePort: srcPort, DestinationPort: dstPort,
		}}}
	case 17:
		f.L4 = &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{
			SourcePort: srcPort, DestinationPort: dstPort,
		}}}
	}

	if verdict == flowpb.Verdict_DROPPED {
		f.DropReasonDesc = flowpb.DropReason_POLICY_DENIED
	}
	return f
}

func ipString(b []byte, family uint8) string {
	if family == 4 {
		return net.IP(b[:4]).String()
	}
	return net.IP(b[:16]).String()
}

func beU16(v uint16) uint16 { return (v&0xff)<<8 | (v&0xff00)>>8 }

func localPodName(unit string, cgid uint64) string {
	if unit != "" {
		return unit
	}
	return "cgroup-" + strconv.FormatUint(cgid, 16)
}

func CgroupIdentity(cgid uint64) uint32 {
	h := fnv.New32a()
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], cgid)
	_, _ = h.Write(b[:])
	v := h.Sum32()
	if v < 256 {
		v += 256
	}
	return v
}

func FormatLabels(unit string, cgid uint64) []string {
	out := []string{
		"k8s:io.kubernetes.pod.namespace=microseg",
		fmt.Sprintf("microseg.cgroup_id=%d", cgid),
	}
	if unit != "" {
		// k8s:app is the label Hubble UI reads to name a service-map node.
		// Without it, every endpoint shows as "No app name" even though
		// PodName is set. microseg.unit stays for our own filtering.
		out = append(out, "microseg.unit="+unit, "k8s:app="+unit)
	}
	return out
}
