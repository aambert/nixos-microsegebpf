// SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
// SPDX-License-Identifier: (MIT AND GPL-2.0-only)
//
// Userspace permission grant: MIT. Kernel permission grant: GPL-2.0
// (the BPF subsystem refuses to load programs that don't declare a
// GPL-compatible runtime LICENSE string when they call GPL-only
// helpers, which we do — bpf_loop, bpf_skb_cgroup_id, etc).
// The runtime LICENSE[] below carries "Dual MIT/GPL" which the
// kernel matches against its is_bpf_program_license_gplcompatible()
// allow-list (kernel/bpf/core.c).
//
// microseg cgroup-skb datapath, v2.
//
// Differences vs v1:
//   - Per-direction × per-family LPM_TRIE maps (CIDR support)
//   - IPv6 fully wired
//   - Port range expansion handled in userspace (single map per family)
//
// LPM_TRIE key layout: the kernel's BPF_MAP_TYPE_LPM_TRIE matches the
// first `prefix_len` bits of the key starting after the prefix_len
// header itself. We pack `(cgroup_id, peer_port, protocol)` ahead of the
// IP so an entry can pin those three to exact values (prefix_len ≥ 88
// for v4 / v6) while still allowing the IP suffix to vary.
//
//   exact-match prefix bits = sizeof(cgroup_id+port+proto) * 8 = 88
//   v4 entry prefix_len     = 88 + ip4_mask  (88..120)
//   v6 entry prefix_len     = 88 + ip6_mask  (88..216)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define SKB_DROP    0
#define SKB_PASS    1

enum verdict {
    V_ALLOW = 0,
    V_DROP  = 1,
    V_LOG   = 2,
};

enum direction {
    D_EGRESS  = 0,
    D_INGRESS = 1,
};

#define POLICY_HEADER_BITS 88   // cgroup_id(64) + peer_port(16) + protocol(8)

struct lpm_v4_key {
    __u32 prefix_len;
    __u64 cgroup_id;
    __u16 peer_port;
    __u8  protocol;
    __u8  ip[4];
} __attribute__((packed));

struct lpm_v6_key {
    __u32 prefix_len;
    __u64 cgroup_id;
    __u16 peer_port;
    __u8  protocol;
    __u8  ip[16];
} __attribute__((packed));

struct policy_value {
    __u8 verdict;
    __u8 pad[3];
    __u32 policy_id;
};

struct flow_event {
    __u64 ts_ns;
    __u64 cgroup_id;
    __u8  family;       // 4 or 6
    __u8  direction;
    __u8  verdict;
    __u8  protocol;
    __u16 src_port;
    __u16 dst_port;
    __u32 policy_id;
    __u8  src_ip[16];   // big enough for v6; v4 occupies first 4
    __u8  dst_ip[16];
};

#define POLICY_MAP(name) \
    struct { \
        __uint(type, BPF_MAP_TYPE_LPM_TRIE); \
        __type(key, struct lpm_v4_key); \
        __type(value, struct policy_value); \
        __uint(max_entries, 65536); \
        __uint(map_flags, BPF_F_NO_PREALLOC); \
        __uint(pinning, LIBBPF_PIN_BY_NAME); \
    } name SEC(".maps")

#define POLICY_MAP_V6(name) \
    struct { \
        __uint(type, BPF_MAP_TYPE_LPM_TRIE); \
        __type(key, struct lpm_v6_key); \
        __type(value, struct policy_value); \
        __uint(max_entries, 65536); \
        __uint(map_flags, BPF_F_NO_PREALLOC); \
        __uint(pinning, LIBBPF_PIN_BY_NAME); \
    } name SEC(".maps")

POLICY_MAP(egress_v4);
POLICY_MAP(ingress_v4);
POLICY_MAP_V6(egress_v6);
POLICY_MAP_V6(ingress_v6);

// Maximum number of TLS-bearing destination ports the agent can be
// configured with. Bumping this requires both a verifier-friendly
// re-roll of `is_tls_port` and a userspace cap update.
#define MAX_TLS_PORTS 8

struct default_cfg {
    __u8 default_egress_verdict;
    __u8 default_ingress_verdict;
    __u8 emit_allow_events;
    // When non-zero, drop every UDP egress packet whose destination
    // port is in `tls_ports` below. Used to force QUIC clients to
    // fall back to TCP/TLS, where our SNI parser actually works.
    __u8 block_quic;
    // Number of valid entries in `tls_ports`. 0 disables TLS peeking.
    __u8 num_tls_ports;
    __u8 pad[3];
    // Destination ports that the agent treats as carrying TLS. The
    // SNI/ALPN parser fires on TCP egress to any of these ports; if
    // `block_quic` is set, UDP egress to the same ports is dropped
    // outright. Replaces the previous hard-coded 443/8443 check.
    __u16 tls_ports[MAX_TLS_PORTS];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct default_cfg);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} microseg_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

// TLS-aware deny lists.
//
// Two maps with different shapes because the matching semantics differ:
//
//   tls_sni_lpm  — LPM_TRIE on the reversed SNI hostname. Letting the
//                  trie do prefix matching gives us wildcard support
//                  for free: a userspace pattern "*.example.com"
//                  inserts the reversed bytes "moc.elpmaxe." with
//                  prefix_len covering all 12 bytes; the lookup with
//                  reversed("mail.example.com") = "moc.elpmaxe.liam"
//                  matches that prefix. Exact patterns are
//                  distinguished by appending a NUL terminator
//                  ("moc.elpmaxe\0"), which prevents a longer
//                  reversed lookup string from matching.
//
//   tls_alpn_deny — HASH on a 64-bit FNV-1a hash. ALPN identifiers
//                   are short, fixed-vocabulary (h2, http/1.1, h3,
//                   imap, smtp, ...) and never wildcarded, so the
//                   cheaper hash lookup wins.
#define MAX_SNI_NAME_BYTES 256

struct sni_lpm_key {
    __u32 prefix_len;            // bits, NOT bytes (LPM convention)
    __u8  name[MAX_SNI_NAME_BYTES];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct sni_lpm_key);
    __type(value, struct policy_value);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tls_sni_lpm SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct policy_value);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tls_alpn_deny SEC(".maps");

// Per-CPU scratch for the SNI LPM key. The key is 260 bytes
// (prefix_len + 256-byte name); putting it on the stack alongside the
// rest of the parser frame blows the 512-byte BPF stack budget. A
// PERCPU_ARRAY of size 1 gives us a per-thread, lock-free working
// area whose lifetime is the program invocation.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct sni_lpm_key);
    __uint(max_entries, 1);
} sni_scratch SEC(".maps");

const struct flow_event *unused_flow_event __attribute__((unused));
const struct lpm_v4_key *unused_v4 __attribute__((unused));
const struct lpm_v6_key *unused_v6 __attribute__((unused));
const struct sni_lpm_key *unused_sni __attribute__((unused));

// "Dual MIT/GPL" is one of the strings the kernel BPF verifier
// recognises as GPL-compatible — see is_bpf_program_license_gplcompatible
// in kernel/bpf/core.c. It lets us use GPL-only helpers (bpf_loop,
// bpf_skb_cgroup_id, etc) while keeping the source MIT-licensed.
char LICENSE[] SEC("license") = "Dual MIT/GPL";

static __always_inline struct default_cfg *get_cfg(void)
{
    __u32 k = 0;
    return bpf_map_lookup_elem(&microseg_cfg, &k);
}

// Bounded linear scan over the configured TLS port list. With
// MAX_TLS_PORTS = 8 the verifier unrolls cleanly and the cost is
// trivial vs the bpf_map_lookup_elem we're protecting.
static __always_inline bool is_tls_port(struct default_cfg *cfg, __u16 port_h)
{
    if (!cfg) return false;
    #pragma unroll
    for (int i = 0; i < MAX_TLS_PORTS; i++) {
        if (i >= cfg->num_tls_ports) return false;
        if (cfg->tls_ports[i] == port_h) return true;
    }
    return false;
}

// ============================================================
// TLS ClientHello peeking — SNI + ALPN matching.
//
// We never decrypt anything. The ClientHello is the very first
// handshake message a TLS client sends and is fully cleartext (with
// the TLS 1.3 ECH extension being the long-term threat — see README's
// "limitations" section). Reading SNI and ALPN from it lets us drop
// connections by hostname/protocol without an L7 proxy.
//
// The parser is a state machine over `bpf_skb_load_bytes` reads —
// safer for the verifier than juggling `data` / `data_end` pointers
// through a chain of variable-length TLS fields. We cap every loop
// (extensions, ALPN entries, hash bytes) so the verifier can prove
// termination.
// ============================================================

#define TLS_CONTENT_HANDSHAKE   0x16
#define TLS_HS_CLIENT_HELLO     0x01
#define TLS_EXT_SNI             0x0000
#define TLS_EXT_ALPN            0x0010
#define MAX_TLS_HASH_BYTES      256
// Tight bounds: the BPF verifier refuses big #pragma unroll'd loops
// that produce branch offsets outside the 16-bit signed range. Kept
// small so the parser fits; in practice ClientHellos have <16 ext.
#define MAX_TLS_EXTENSIONS      16
#define MAX_ALPN_ENTRIES        4

struct fnv_ctx {
    struct __sk_buff *skb;
    __u32 off;
    __u32 len;
    __u64 hash;
};

// bpf_loop callback: hash one byte. Returns 1 to break the loop when
// we have consumed the requested length.
static long fnv_step(__u32 i, struct fnv_ctx *ctx)
{
    if (i >= ctx->len)
        return 1;
    __u8 b;
    if (bpf_skb_load_bytes(ctx->skb, ctx->off + i, &b, 1) < 0)
        return 1;
    ctx->hash ^= (__u64)b;
    ctx->hash *= 0x100000001b3ULL;
    return 0;
}

// FNV-1a 64-bit. Userspace mirrors this byte-for-byte; both ends must
// agree on the result for a HASH map lookup to succeed.
static __always_inline __u64 fnv64a(struct __sk_buff *skb, __u32 off, __u32 len)
{
    struct fnv_ctx ctx = {
        .skb = skb,
        .off = off,
        .len = len,
        .hash = 0xcbf29ce484222325ULL,
    };
    bpf_loop(MAX_TLS_HASH_BYTES, fnv_step, &ctx, 0);
    return ctx.hash;
}

static __always_inline __u16 load_be16(struct __sk_buff *skb, __u32 off)
{
    __u8 b[2];
    if (bpf_skb_load_bytes(skb, off, b, 2) < 0)
        return 0;
    return ((__u16)b[0] << 8) | b[1];
}

static __always_inline __u8 load_u8(struct __sk_buff *skb, __u32 off)
{
    __u8 b;
    if (bpf_skb_load_bytes(skb, off, &b, 1) < 0)
        return 0;
    return b;
}

// SNI loader context: pointer into the per-CPU scratch + skb read
// state. The reversed form is what we look up in the LPM trie —
// Cilium uses the same trick for FQDN matching, because LPM matches
// a *prefix* of the key and DNS hierarchy nests right-to-left.
struct sni_load_ctx {
    struct __sk_buff *skb;
    __u32 src_off;
    __u32 src_len;
    struct sni_lpm_key *key;   // points into the per-CPU scratch
};

static long sni_load_byte(__u32 i, struct sni_load_ctx *ctx)
{
    if (i >= ctx->src_len) return 1;
    __u8 b;
    if (bpf_skb_load_bytes(ctx->skb, ctx->src_off + i, &b, 1) < 0) return 1;
    // Lowercase: SNI is case-insensitive per RFC 6066 §3 and modern
    // clients already send lowercase, but normalising in-kernel makes
    // userspace policy authoring simpler.
    if (b >= 'A' && b <= 'Z') b += 32;
    // Reverse: position from the end of the input. The
    // unconditional mask is what the verifier accepts as a proof
    // that `j` fits the 256-byte buffer — caller already enforces
    // src_len <= MAX_SNI_NAME_BYTES so the mask is semantically a
    // no-op for valid inputs, but it's load-bearing for the verifier.
    __u32 j = (ctx->src_len - 1 - i) & (MAX_SNI_NAME_BYTES - 1);
    ctx->key->name[j] = b;
    return 0;
}

// sni_lpm_check returns true if the SNI hostname at (off, len) in the
// skb matches a deny entry in tls_sni_lpm. False on any failure
// (read error, oversized name, no match).
static __always_inline bool sni_lpm_check(struct __sk_buff *skb,
                                          __u32 off, __u16 len)
{
    if (len == 0 || len > MAX_SNI_NAME_BYTES) return false;

    __u32 zero = 0;
    struct sni_lpm_key *key = bpf_map_lookup_elem(&sni_scratch, &zero);
    if (!key) return false;

    // Zero the whole key. Two reasons:
    //   1. LPM lookup compares against the entry's prefix_len bits;
    //      a stale name suffix from a previous packet would corrupt
    //      the match.
    //   2. The lookup's prefix_len must be >= every entry's prefix_len
    //      for that entry to be eligible. Setting it to the full
    //      MAX_SNI_NAME_BYTES * 8 makes every populated entry
    //      reachable; the kernel still picks the longest match.
    __builtin_memset(key, 0, sizeof(*key));
    key->prefix_len = MAX_SNI_NAME_BYTES * 8;

    struct sni_load_ctx ctx = {
        .skb = skb,
        .src_off = off,
        .src_len = len,
        .key = key,
    };
    bpf_loop(MAX_SNI_NAME_BYTES, sni_load_byte, &ctx, 0);

    struct policy_value *pv = bpf_map_lookup_elem(&tls_sni_lpm, key);
    return pv && pv->verdict == V_DROP;
}

// Per-extension walker context for bpf_loop.
struct ext_loop_ctx {
    struct __sk_buff *skb;
    __u32 off;
    __u32 ext_end;
    __u8  verdict;
};

// One iteration: read extension header, dispatch SNI / ALPN / skip.
// Returns 0 to keep iterating, 1 to stop (out of buffer or matched).
static long walk_extension(__u32 i, struct ext_loop_ctx *ctx)
{
    if (ctx->off + 4 > ctx->ext_end) return 1;
    __u16 ext_type = load_be16(ctx->skb, ctx->off);
    __u16 ext_len  = load_be16(ctx->skb, ctx->off + 2);
    __u32 ext_data = ctx->off + 4;
    ctx->off = ext_data + ext_len;

    if (ext_type == TLS_EXT_SNI) {
        __u8 name_type = load_u8(ctx->skb, ext_data + 2);
        if (name_type != 0) return 0;
        __u16 name_len = load_be16(ctx->skb, ext_data + 3);
        if (name_len == 0 || name_len > MAX_SNI_NAME_BYTES) return 0;
        if (sni_lpm_check(ctx->skb, ext_data + 5, name_len)) {
            ctx->verdict = V_DROP;
            return 1;
        }
    } else if (ext_type == TLS_EXT_ALPN) {
        __u16 list_len = load_be16(ctx->skb, ext_data);
        __u32 ap = ext_data + 2;
        __u32 ap_end = ap + list_len;
        // Only the first ALPN entry — most clients send a short list
        // (h2, http/1.1) and matching the first is enough to catch
        // h2-only beacons. Reduces verifier complexity.
        if (ap < ap_end) {
            __u8 plen = load_u8(ctx->skb, ap);
            if (plen > 0 && plen <= MAX_TLS_HASH_BYTES) {
                __u64 h = fnv64a(ctx->skb, ap + 1, plen);
                struct policy_value *pv = bpf_map_lookup_elem(&tls_alpn_deny, &h);
                if (pv && pv->verdict == V_DROP) {
                    ctx->verdict = V_DROP;
                    return 1;
                }
            }
        }
    }
    return 0;
}

// Returns V_DROP if the ClientHello at `payload_off` matches a deny
// entry in either tls_sni_lpm or tls_alpn_deny. Returns V_ALLOW
// otherwise (including all malformed / non-TLS cases — peeking is a
// best-effort augmentation, not a primary verdict).
static __always_inline __u8 tls_check(struct __sk_buff *skb,
                                      __u32 payload_off, __u32 payload_len)
{
    // Need at minimum: TLS record header (5) + handshake header (4) +
    // client_version (2) + random (32) = 43 bytes.
    if (payload_len < 43)
        return V_ALLOW;

    __u8 rec[5];
    if (bpf_skb_load_bytes(skb, payload_off, rec, 5) < 0)
        return V_ALLOW;
    if (rec[0] != TLS_CONTENT_HANDSHAKE) return V_ALLOW;
    if (rec[1] != 0x03) return V_ALLOW;          // TLS major version

    if (load_u8(skb, payload_off + 5) != TLS_HS_CLIENT_HELLO)
        return V_ALLOW;

    // Walk the ClientHello to its extensions block. Each variable-length
    // field carries its own length prefix; we trust those length
    // prefixes and bail out cleanly on the first read failure.
    __u32 off = payload_off + 5 + 4;             // skip record + hs hdr
    off += 2 + 32;                                // client_version + random

    __u8 sid_len = load_u8(skb, off);
    off += 1 + sid_len;

    __u16 cs_len = load_be16(skb, off);
    off += 2 + cs_len;

    __u8 cm_len = load_u8(skb, off);
    off += 1 + cm_len;

    __u16 ext_total = load_be16(skb, off);
    off += 2;
    __u32 ext_end = off + ext_total;

    // Drive the extension walk through bpf_loop so the verifier sees
    // a single iteration callback instead of an unrolled body × N.
    struct ext_loop_ctx ctx = {
        .skb = skb, .off = off, .ext_end = ext_end, .verdict = V_ALLOW,
    };
    bpf_loop(MAX_TLS_EXTENSIONS, walk_extension, &ctx, 0);
    return ctx.verdict;
}

static __always_inline void emit_event(__u64 cgid,
                                       __u8 family,
                                       __u8 *src_ip, __u8 *dst_ip,
                                       __u16 src_port, __u16 dst_port,
                                       __u8 proto, __u8 dir,
                                       __u8 verdict, __u32 policy_id,
                                       struct default_cfg *cfg)
{
    if (verdict == V_ALLOW && cfg && !cfg->emit_allow_events)
        return;

    struct flow_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    __builtin_memset(e, 0, sizeof(*e));
    e->ts_ns     = bpf_ktime_get_ns();
    e->cgroup_id = cgid;
    e->family    = family;
    e->direction = dir;
    e->verdict   = verdict;
    e->protocol  = proto;
    e->src_port  = src_port;
    e->dst_port  = dst_port;
    e->policy_id = policy_id;

    int n = (family == 4) ? 4 : 16;
    for (int i = 0; i < 16; i++) {
        e->src_ip[i] = (i < n) ? src_ip[i] : 0;
        e->dst_ip[i] = (i < n) ? dst_ip[i] : 0;
    }

    bpf_ringbuf_submit(e, 0);
}

static __always_inline int handle_v4(struct __sk_buff *skb, __u8 dir)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *ip = data;
    if ((void *)(ip + 1) > data_end) return SKB_PASS;
    if (ip->ihl < 5) return SKB_PASS;
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return SKB_PASS;

    void *l4 = (void *)ip + (ip->ihl * 4);
    __u16 sport = 0, dport = 0;
    __u8 tcp_doff = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *t = l4;
        if ((void *)(t + 1) > data_end) return SKB_PASS;
        sport = t->source; dport = t->dest;
        tcp_doff = t->doff;
    } else {
        struct udphdr *u = l4;
        if ((void *)(u + 1) > data_end) return SKB_PASS;
        sport = u->source; dport = u->dest;
    }

    __u64 cgid = bpf_skb_cgroup_id(skb);
    struct lpm_v4_key key = {};
    key.prefix_len = POLICY_HEADER_BITS + 32;
    key.cgroup_id  = cgid;
    key.protocol   = ip->protocol;

    __u32 peer_ip;
    if (dir == D_EGRESS) {
        key.peer_port = dport;
        peer_ip = ip->daddr;
    } else {
        key.peer_port = sport;
        peer_ip = ip->saddr;
    }
    __builtin_memcpy(key.ip, &peer_ip, 4);

    void *map = (dir == D_EGRESS) ? (void *)&egress_v4 : (void *)&ingress_v4;
    struct policy_value *pv = bpf_map_lookup_elem(map, &key);

    struct default_cfg *cfg = get_cfg();
    __u8 verdict;
    __u32 policy_id = 0;

    if (pv) {
        verdict = pv->verdict;
        policy_id = pv->policy_id;
    } else if (cfg) {
        verdict = (dir == D_EGRESS) ? cfg->default_egress_verdict
                                    : cfg->default_ingress_verdict;
    } else {
        verdict = V_ALLOW;
    }

    // TLS peek (TCP) and QUIC blanket-drop (UDP) — both gated by the
    // configurable TLS port list. Skipped on ingress.
    if (verdict != V_DROP && dir == D_EGRESS) {
        __u16 dport_h = bpf_ntohs(dport);
        if (is_tls_port(cfg, dport_h)) {
            if (ip->protocol == IPPROTO_TCP && tcp_doff >= 5) {
                __u32 payload_off = (ip->ihl * 4) + (tcp_doff * 4);
                __u32 total = skb->len;
                if (total > payload_off) {
                    __u8 tls_v = tls_check(skb, payload_off, total - payload_off);
                    if (tls_v == V_DROP) {
                        verdict = V_DROP;
                        if (policy_id == 0) policy_id = 0xFFFFFFFE; // TLS sentinel
                    }
                }
            } else if (ip->protocol == IPPROTO_UDP && cfg && cfg->block_quic) {
                // UDP to a TLS port + block_quic = treat as QUIC and drop.
                // Browsers retry on TCP/TLS, where SNI matching works.
                verdict = V_DROP;
                if (policy_id == 0) policy_id = 0xFFFFFFFD; // QUIC sentinel
            }
        }
    }

    __u8 src[4], dst[4];
    __builtin_memcpy(src, &ip->saddr, 4);
    __builtin_memcpy(dst, &ip->daddr, 4);
    emit_event(cgid, 4, src, dst, sport, dport,
               ip->protocol, dir, verdict, policy_id, cfg);

    return (verdict == V_DROP) ? SKB_DROP : SKB_PASS;
}

static __always_inline int handle_v6(struct __sk_buff *skb, __u8 dir)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ipv6hdr *ip6 = data;
    if ((void *)(ip6 + 1) > data_end) return SKB_PASS;
    if (ip6->nexthdr != IPPROTO_TCP && ip6->nexthdr != IPPROTO_UDP)
        return SKB_PASS;

    void *l4 = (void *)(ip6 + 1);
    __u16 sport = 0, dport = 0;
    __u8 tcp_doff = 0;
    if (ip6->nexthdr == IPPROTO_TCP) {
        struct tcphdr *t = l4;
        if ((void *)(t + 1) > data_end) return SKB_PASS;
        sport = t->source; dport = t->dest;
        tcp_doff = t->doff;
    } else {
        struct udphdr *u = l4;
        if ((void *)(u + 1) > data_end) return SKB_PASS;
        sport = u->source; dport = u->dest;
    }

    __u64 cgid = bpf_skb_cgroup_id(skb);
    struct lpm_v6_key key = {};
    key.prefix_len = POLICY_HEADER_BITS + 128;
    key.cgroup_id  = cgid;
    key.protocol   = ip6->nexthdr;

    if (dir == D_EGRESS) {
        key.peer_port = dport;
        __builtin_memcpy(key.ip, &ip6->daddr, 16);
    } else {
        key.peer_port = sport;
        __builtin_memcpy(key.ip, &ip6->saddr, 16);
    }

    void *map = (dir == D_EGRESS) ? (void *)&egress_v6 : (void *)&ingress_v6;
    struct policy_value *pv = bpf_map_lookup_elem(map, &key);

    struct default_cfg *cfg = get_cfg();
    __u8 verdict;
    __u32 policy_id = 0;

    if (pv) {
        verdict = pv->verdict;
        policy_id = pv->policy_id;
    } else if (cfg) {
        verdict = (dir == D_EGRESS) ? cfg->default_egress_verdict
                                    : cfg->default_ingress_verdict;
    } else {
        verdict = V_ALLOW;
    }

    if (verdict != V_DROP && dir == D_EGRESS) {
        __u16 dport_h = bpf_ntohs(dport);
        if (is_tls_port(cfg, dport_h)) {
            if (ip6->nexthdr == IPPROTO_TCP && tcp_doff >= 5) {
                __u32 payload_off = sizeof(struct ipv6hdr) + (tcp_doff * 4);
                __u32 total = skb->len;
                if (total > payload_off) {
                    __u8 tls_v = tls_check(skb, payload_off, total - payload_off);
                    if (tls_v == V_DROP) {
                        verdict = V_DROP;
                        if (policy_id == 0) policy_id = 0xFFFFFFFE;
                    }
                }
            } else if (ip6->nexthdr == IPPROTO_UDP && cfg && cfg->block_quic) {
                verdict = V_DROP;
                if (policy_id == 0) policy_id = 0xFFFFFFFD;
            }
        }
    }

    __u8 src[16], dst[16];
    __builtin_memcpy(src, &ip6->saddr, 16);
    __builtin_memcpy(dst, &ip6->daddr, 16);
    emit_event(cgid, 6, src, dst, sport, dport,
               ip6->nexthdr, dir, verdict, policy_id, cfg);

    return (verdict == V_DROP) ? SKB_DROP : SKB_PASS;
}

static __always_inline int handle_skb(struct __sk_buff *skb, __u8 dir)
{
    if (skb->protocol == bpf_htons(ETH_P_IP))
        return handle_v4(skb, dir);
    if (skb->protocol == bpf_htons(ETH_P_IPV6))
        return handle_v6(skb, dir);
    return SKB_PASS;
}

SEC("cgroup_skb/egress")
int microseg_egress(struct __sk_buff *skb)
{
    return handle_skb(skb, D_EGRESS);
}

SEC("cgroup_skb/ingress")
int microseg_ingress(struct __sk_buff *skb)
{
    return handle_skb(skb, D_INGRESS);
}
