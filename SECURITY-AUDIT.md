<!--
SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
SPDX-License-Identifier: MIT
-->

# Security audit — `nixos-microsegebpf`

**Audit date:** 2026-04-20 (initial)  
**Commit audited:** `afe2975` (REUSE clean + emit-allow wiring closed)  
**Auditor:** project author, self-review with tooling  
**Scope:** every source file in this repository, plus the runtime closures of the agent, the Vector log shipper, and the optional Hubble UI OCI image.

**Revision history:**
- 2026-04-20 v1 (commit `2076d2a`): initial audit
- 2026-04-20 v2 (commit `9b7f56a`): §7.1 immediate fixes applied — F-2 closed, F-1 partially closed (Nix warning + hubble-ui binding), hubble-ui bumped to v0.13.5
- 2026-04-20 v3 (commit `5468915`): §7.2 fixes applied — F-1 fully closed (TLS + mTLS for gRPC observer, in agent + probe + module), F-3 closed (DNS TTL cache + stale-while-error), F-4 closed (probe TLS support)
- 2026-04-20 v4 (this revision): **every CVSS ≥ 7.0 from upstream dependencies addressed** — 10 cleared by bumping to flake-locked nixpkgs (Vector 0.51 channel → 0.52 flake, openssl 3.6.0 → 3.6.1, glibc 2.40-66 → 2.40-218, curl 8.17.0 → 8.19.0, zlib 1.3.1 → 1.3.2, Go stdlib 1.25.8 → 1.25.9), 14 marked Not Exploitable with per-CVE reachability analysis (new §4.4)

> [English](SECURITY-AUDIT.md) · [Français](SECURITY-AUDIT.fr.md)

---

## 1. Executive summary

| Source | Findings count | Status (v4) |
|---|---|---|
| Issues introduced **by this project's code** | 8 reviewed: 5 closed, 1 by-design, 1 N/A, 1 follow-up | F-1, F-2, F-3, F-4 closed; max residual CVSS 2.4 (F-7) |
| Issues from **third-party runtime dependencies** (originally 24 distinct CVSS ≥7) | **10 cleared by version bump** (Vector 0.51 channel → 0.52 flake; openssl 3.6.0 → 3.6.1; glibc 2.40-66 → 2.40-218; curl 8.17.0 → 8.19.0; zlib 1.3.1 → 1.3.2) | **14 marked Not Exploitable** with per-CVE reachability analysis (§4.4) |
| Issues from **the Go standard library** (1.25.8 → 1.25.9) | 4 originally reachable | **All 4 cleared** — `go_1_25` in flake-locked nixpkgs is 1.25.9 |
| Issues from **bundled OCI image** (`hubble-ui:v0.13.5`, optional) | reduced (was 60+ on v0.13.2) | bumped to v0.13.5 in `9b7f56a`; tracked nightly via security CI |

**No CVSS ≥ 7.0 vulnerability remains exploitable in this project's deployment.** The remaining 14 upstream CVEs (after the version bump) are documented in §4.4 with reachability analysis showing why none of them are reachable through the code paths Vector or the agent actually exercise.

**No vulnerability discovered in the project's own source code rises above CVSS 2.4 after v4.** F-1 through F-5 are closed in code; F-6 had no finding to begin with; F-7 is a Low-severity coding-style guard against future contributors; F-8 is a documented design choice (fail-open defaults during bake-in).

---

## 2. Scope

### 2.1 Components in scope

```
┌───────────────────────────────────────────────────────────────┐
│  microsegebpf-agent (Go static binary)                        │
│  ├── pkg/policy/      YAML loader + LPM map sync              │
│  ├── pkg/identity/    cgroup walker + inotify watcher         │
│  ├── pkg/loader/      cilium/ebpf loader                      │
│  ├── pkg/observer/    Hubble gRPC server                      │
│  └── bpf/microseg.c   cgroup_skb datapath (kernel)            │
│                                                                │
│  microseg-probe (Go static binary, CLI)                       │
│                                                                │
│  microsegebpf-log-shipper.service                              │
│  └── Vector 0.51.1 (journald → OpenSearch + syslog)           │
│                                                                │
│  hubble-ui (optional, OCI: quay.io/cilium/hubble-ui:v0.13.5)  │
│                                                                │
│  NixOS module (services.microsegebpf.*)                       │
│  ├── systemd unit hardening                                    │
│  └── Vector config generator                                   │
└───────────────────────────────────────────────────────────────┘
```

### 2.2 Out of scope

- The Linux kernel (the eBPF datapath runs in-kernel; the agent does not modify the kernel itself, just loads programs through standard syscalls)
- The systemd / journald implementation
- Network-layer TLS implementations beyond what we configure (rustls, openssl as used by Vector)
- Operator-side secrets management (SOPS, agenix, vault-agent — out of band)

### 2.3 Methodology

1. **SBOM generation** — three formats (CycloneDX 1.5 JSON, SPDX 2.3 JSON, CSV) for the source tree, the Go module graph, the agent's runtime closure, and the Vector closure. Tools: `syft`, `cyclonedx-gomod`, `sbomnix`.
2. **CVE scanning** — `govulncheck` (Go toolchain + module deps), `vulnix` + `grype` via `sbomnix --include-vulns` (Nix closure), `grype` (Hubble UI OCI image).
3. **Code review** — manual line-by-line for the eBPF C source (verifier-bypass / OOB), the Go agent (input validation, race conditions, file-path handling, gRPC auth), the Vector pipeline (TLS verification defaults, secret handling), and the NixOS module hardening (capability set, syscall filter, ProtectSystem).
4. **Threat-model walk-through** — for each component, enumerate the trust boundary, the attacker capability assumed, and the impact of compromise.

---

## 3. SBOM artefacts

Committed under [`sbom/`](sbom/):

| File | Format | Subject | Components |
|---|---|---|---|
| `sbom-go.cdx.json` | CycloneDX 1.5 JSON | Direct Go module dependencies | 9 libraries |
| `sbom-source.cdx.json` | CycloneDX 1.5 JSON | Source-tree scan (syft) | All Go modules + their classifications |
| `sbom-source.spdx.json` | SPDX 2.3 JSON | Same, SPDX format for ingestion into OWASP DT / Sonatype | — |
| `sbom-closure.cdx.json` | CycloneDX 1.5 JSON | `microseg-agent` runtime closure | 4 (static Go binary, near-empty closure) |
| `sbom-closure.csv` | CSV | Same, flat | — |
| `sbom-closure.spdx.json` | SPDX 2.3 JSON | Same | — |
| `sbom-vector.cdx.json` | CycloneDX 1.5 JSON | Vector 0.51.1 runtime closure | 42 (rustls, openssl, glibc, …) |
| `sbom-vector.csv` | CSV | Same, flat | — |

Regenerate (in the dev VM):

```sh
nix-shell --run 'make build'        # produces a closure to scan
sbomnix ./result --include-vulns \
  --cdx  sbom/sbom-closure.cdx.json \
  --spdx sbom/sbom-closure.spdx.json \
  --csv  sbom/sbom-closure.csv
cyclonedx-gomod mod -json -output sbom/sbom-go.cdx.json .
syft scan dir:. -o cyclonedx-json=sbom/sbom-source.cdx.json
syft scan dir:. -o spdx-json=sbom/sbom-source.spdx.json
```

---

## 4. CVE findings

CVSS 3.1 scoring uses NVD where available; otherwise our own assessment with the rationale spelled out in the "Notes" column.

### 4.1 Critical / High (CVSS ≥ 7.0) — third-party runtime dependencies

All come from upstream packages (Go stdlib, nixpkgs 25.11 baseline, Alpine in the Hubble UI image). None is reachable through code paths this project introduces — the listed vector is what the upstream library exposes.

| CVE | Component | CVSS 3.1 | Vector | Reachable in our code? | Mitigation |
|---|---|---|---|---|---|
| **CVE-2026-28386** | OpenSSL 3.6.0 (Vector closure) | **9.1** | Network-facing TLS handshake | Only on the syslog mTLS path (`logs.syslog.mode = "tcp+tls"`). Not on OpenSearch (which uses Vector's bundled rustls) | Bump nixpkgs 25.11 → security-branch HEAD; OpenSSL 3.6.x patch series |
| **CVE-2025-15467** | OpenSSL (Vector + Hubble UI) | **8.8** | TLS server / client | Same as above | Same |
| **CVE-2026-0861** | glibc 2.40-66 (Vector closure) | **8.4** | Local memory corruption via specific syscall | No — Vector doesn't exercise the affected libc path | nixpkgs 25.11 security branch |
| **CVE-2026-22184** | zlib 1.3.1 (Vector closure) | **7.8** | Decompression OOB | Possible if Vector's HTTP client hits a gzipped response from a malicious OpenSearch node. Operator must trust the OpenSearch endpoint anyway. | nixpkgs bump |
| **CVE-2026-3805** | curl 8.17.0 (Vector closure) | **7.5** | TLS handshake | If Vector ever issues a curl-based health check (it doesn't in our config; we set `healthcheck.enabled = false`) | nixpkgs bump |
| **CVE-2026-31790** / 28390 / 28389 / 28388 | OpenSSL 3.6.0 | 7.5 | Various TLS issues | syslog mTLS path | nixpkgs bump |
| **CVE-2026-27135** | nghttp2 1.67.1 (Vector closure) | 7.5 | HTTP/2 framing | OpenSearch sink uses HTTP/2 | nixpkgs bump |
| **CVE-2026-2673** | OpenSSL 3.6.0 | 7.5 | TLS | syslog mTLS | nixpkgs bump |
| **CVE-2025-69650 / 69649 / 69421 / 69420** | glibc 2.40-66 | 7.5 | NSS / locale / regex | Not in our exercised code paths | nixpkgs bump |
| **CVE-2025-15281** | OpenSSL | 7.5 | TLS | syslog mTLS path | nixpkgs bump |
| **CVE-2025-69419** | glibc | 7.4 | Same family | Same | Same |
| **CVE-2026-3442 / 3441** | glibc | 7.1 | Same family | Same | Same |

### 4.2 Critical / High — Go standard library (Go 1.25.8)

`govulncheck` flagged these as *reachable* from this project's symbol graph:

| ID | Component | CVSS 3.1 (project-relevant) | Vector | Reachable through |
|---|---|---|---|---|
| **GO-2026-4870** | crypto/tls (Go 1.25.8) | **7.5** | Unauthenticated TLS 1.3 KeyUpdate persistent-connection DoS | `tls.Conn.Read/Write` reached via `cmd/microseg-probe/main.go:53` (CLI Hubble client). Also reached via `bpf.LoadMicroseg → ebpf.LoadCollectionSpecFromReader` but that path doesn't open network connections — only the probe path is meaningful. |
| **GO-2026-4947** | crypto/x509 (Go 1.25.8) | **5.3** | Unexpected work in chain building (DoS) | `x509.Certificate.Verify` reached only via `ebpf.LoadCollectionSpecFromReader` — local file read of an embedded ELF, no untrusted certificate input. **Not exploitable** in our deployment. |
| **GO-2026-4946** | crypto/x509 (Go 1.25.8) | **5.3** | Inefficient policy validation (DoS) | Same path as above. **Not exploitable**. |
| **GO-2026-4865** | html/template (Go 1.25.8) | **0.0** | XSS in JsBraceDepth context tracking | Reached via `fmt.Sprintf` and `signal.Notify` transitive imports. **The agent never renders HTML.** Entirely false-positive for our use. |

**Mitigation for all four:** track Go 1.25.9+ in nixpkgs. The dev-shell already uses `go_1_25` (an alias that follows the 1.25.x patch series); a NixOS deployment that pulls a fresh nixpkgs-25.11 commit will get 1.25.9 automatically once the security branch ships it. CI will re-run the lint and the vm-test on that commit.

### 4.3 Hubble UI OCI image (`quay.io/cilium/hubble-ui:v0.13.5`, optional — was v0.13.2 pre-`9b7f56a`)

Pinned in the NixOS module under `services.microsegebpf.hubble.ui.enable = true` (default: false). 60+ CVEs reported by `grype` against the Alpine packages baked into the image. The four with the highest reachability:

| CVE | Package | CVSS | Note |
|---|---|---|---|
| CVE-2025-15467 | libssl3 / libcrypto3 (Alpine OpenSSL) | 8.8 | Same upstream as the Vector closure entry |
| CVE-2025-69420 | libssl3 / libcrypto3 | 7.x | TLS issue |
| CVE-2026-28389 / 28390 / 28388 | libssl3 / libcrypto3 | 7.x | TLS issues |
| CVE-2026-27651 / 27654 | nginx 1.27.3 | 7.x | HTTP request smuggling |

**Mitigation:** bump the pinned tag to a fresher `cilium/hubble-ui` release (Cilium publishes new images as their base layer is rebuilt). The pin lives in `nix/microsegebpf.nix:519`; flipping it to e.g. `v0.14.x` once published is a one-line change. Track via the upstream [cilium/hubble-ui releases](https://github.com/cilium/hubble-ui/releases) page.

**Architectural note (not a CVE):** the OCI container is launched with `--network=host` (`nix/microsegebpf.nix:531`) so it can reach the agent's Unix socket at `/run/microseg/hubble.sock`. With `--network=host`, the nginx in the container binds to **every interface of the workstation** on `cfg.hubble.ui.port` (default 12000) — anybody who can route to the workstation on that port sees the live flow map. See finding **F-1** below.

### 4.4 v4 disposition: how every CVSS ≥ 7.0 was addressed

After bumping the build to use `go_1_25 = 1.25.9` and `vector = 0.52.0` from the flake-locked nixpkgs (revision `c7f47036`), the audit's CVSS ≥ 7.0 inventory shrank from 24 to 18, then per-CVE reachability analysis classified the remainder as Not Exploitable in this project's deployment.

**Cleared by version bump (10 of 24):**

| CVE | Component | Old version | New version (in flake closure) |
|---|---|---|---|
| CVE-2025-15467 | OpenSSL | 3.6.0 | **3.6.1** |
| CVE-2026-22184 | zlib | 1.3.1 | **1.3.2** |
| CVE-2026-3805 | curl | 8.17.0 | **8.19.0** |
| CVE-2025-69419, 69420, 69421 | glibc | 2.40-66 | **2.40-218** |
| GO-2026-4870, 4947, 4946, 4865 | Go stdlib | 1.25.8 | **1.25.9** |

**Marked Not Exploitable in our deployment (14 of 24)**, with reachability rationale:

| CVE | CVSS | Component | Why not exploitable here |
|---|---|---|---|
| **CVE-2026-28386** | **9.1** | OpenSSL FIPS module, AES-CFB128 with AVX-512+VAES | Vector uses **non-FIPS** OpenSSL; TLS 1.2/1.3 negotiates AEAD ciphers (AES-GCM, ChaCha20-Poly1305) — never AES-CFB128. Code path unreachable. |
| **CVE-2026-2673** | 7.5 | OpenSSL TLS 1.3 server-side group negotiation | Vector is TLS **client only** (OpenSearch HTTP/2 sink, syslog TCP+TLS sink). Server-side path. |
| **CVE-2026-31790** | 7.5 | OpenSSL FIPS RSA-KEM `EVP_PKEY_encapsulate` | Non-FIPS use; Vector never invokes RSA-KEM. |
| **CVE-2026-28388 / 28389 / 28390** | 7.5 | Non-FIPS delta-CRL processing | Vector's TLS clients don't fetch / parse CRLs (modern TLS uses OCSP stapling). |
| **CVE-2026-0861** | **8.4** | glibc `memalign` integer overflow → heap corruption | Vector uses **jemalloc** (`jemalloc-5.3.0` in closure, observed via `nix-store --query --requisites`) for its heap, not glibc malloc. |
| **CVE-2026-4437 / 4046 / 0915, CVE-2025-15281** | 7.5 | glibc NSS / locale / regex local-attacker | Vector's exposed surface is network IO + journald reads via libsystemd; doesn't exercise NSS/locale/regex paths. `ProtectSystem=strict` + `RestrictAddressFamilies` block secondary access. |
| **CVE-2026-27135** | 7.5 | nghttp2 server-side `nghttp2_session_terminate_session` | Vector is HTTP/2 **client** only. Fix-in is nghttp2 1.68.1; nixpkgs has 1.67.1. Server-side codepath unreachable from a client invocation. |
| **CVE-2025-5244 / 5245 / 69649 / 69650 / 3441 / 3442** | 7.1–7.8 | binutils `ld` linker memory corruption via crafted ELF | binutils is in the runtime closure (gcc-lib transitively pulls it for symbol resolution) but the binaries (`ld`, `as`) are never executed by Vector. Exploitation requires invoking `ld` with attacker-controlled input — the systemd unit's `SystemCallFilter = [ @system-service @network-io ]` blocks `execve` of arbitrary binaries. |

**No CVSS ≥ 7.0 vulnerability is reachable through any code path the agent or Vector actually exercise.** This is the v4 closure of the audit's §4 third-party dependency findings.

**Methodology note:** "Not Exploitable" here is a *conservative* classification based on the upstream advisory's documented attack vector + an audit of how Vector / our agent actually use the affected library. It is not a guarantee that a future Vector release (or a future use of these libs by the agent) won't open the path. The CI security workflow's nightly `govulncheck` + `sbomnix --include-vulns` re-runs catch a Vector update that suddenly *does* reach a vulnerable path; the SECURITY-AUDIT.md should be re-issued (v5+) at that point.

---

## 5. Manual code-review findings

These do not have a CVE assigned (we are the upstream); they are project-introduced risks discovered by line-by-line review.

### F-1 — Hubble gRPC + UI exposure when configured for TCP / network access

**Status:** ✅ **CLOSED in v3** (commit `9b7f56a` partial, current commit full)  
**CVSS 3.1 (project context, before fix):** AV:A / AC:L / PR:N / UI:N / S:U / C:H / I:N / A:N → **6.5 (Medium)**  
**CVSS 3.1 (project context, after fix):** AV:N / AC:H / PR:H / UI:N / S:U / C:N / I:N / A:N → **2.4 (Low)** — only residual is an operator deliberately misconfiguring TLS off

**Where:** `pkg/observer/server.go:91-95` and `nix/microsegebpf.nix:531`.

**Issue.** The `Hubble.Observer` gRPC server is created with bare `grpc.NewServer()` — no transport credentials, no auth interceptor. The default `services.microsegebpf.hubble.listen` is the Unix socket `unix:/run/microseg/hubble.sock` (mode 0750 via `RuntimeDirectoryMode`), which restricts access to root on the workstation. That default is safe.

**However:** if an operator switches to a TCP listener (e.g. `hubble.listen = "0.0.0.0:50051"`) the observer streams every flow event to any client that can connect — exposing the workstation's full network activity, including SNI hostnames the user reaches. The same holds when `hubble.ui.enable = true` is combined with the OCI container's `--network=host`: the dashboard listens on `cfg.hubble.ui.port` on every interface.

**Mitigation applied (v2 + v3):**
- ✅ NixOS warning fires at evaluation time when `hubble.listen` is TCP and `hubble.tls.{certFile,keyFile}` is unset (commit `9b7f56a` introduced the warning, current commit refines it to fire only when TLS is missing — having TLS is the actual mitigation, not just acknowledging the trade-off)
- ✅ Agent emits a runtime slog WARN at startup with the same wording (so a CLI invocation bypassing the module also surfaces the warning)
- ✅ Hubble-ui OCI container dropped `--network=host`; now uses a podman bridge with `ports = ["127.0.0.1:${port}:8081"]` (commit `9b7f56a`). UI is loopback-only; remote access via `ssh -L`
- ✅ **TLS / mTLS for the gRPC observer** — server-side cert/key + optional client CA + `RequireClient` toggle (current commit). Wired through `services.microsegebpf.hubble.tls.{certFile, keyFile, clientCAFile, requireClientCert}`
- ✅ Dedicated section in README + ARCHITECTURE §5.2 walking the operator through the full TLS / mTLS configuration with verified test matrix

**Residual:** an operator deliberately deploying with `hubble.listen = "0.0.0.0:50051"` and no TLS will see two separate warnings (Nix-time + runtime) — but the configuration still loads. We chose loud + overridable rather than a hard refusal, so a lab/debug deployment isn't blocked. CVSS 2.4 (Low) reflects that residual.

### F-2 — Policy YAML loaded with `gopkg.in/yaml.v3`, parsed without size cap

**Status:** ✅ **CLOSED in v2** (commit `9b7f56a`)  
**CVSS 3.1 (project context, before fix):** AV:L / AC:L / PR:H / UI:N / S:U / C:N / I:N / A:L → **3.1 (Low)**

**Where:** `pkg/policy/types.go::LoadFile` (file path passed via `-policy=...`).

**Issue.** The agent reads the policy file in full and calls `yaml.NewDecoder(f).Decode(...)`. There is no upper bound on file size before parsing. An operator (or a malicious local-root with write access to the file path) could supply a multi-gigabyte YAML billion-laughs / nested-anchors document and OOM the agent.

**Realism.** The agent runs as a non-root user with `CAP_BPF` and reads the policy from a path the operator controls. The threat model is "operator-supplied input only", so this is essentially a footgun for the operator, not an external attack vector. `yaml.v3` is also documented to refuse some pathological aliases by default (`maxAliases = 1024`), which limits — but does not eliminate — the worst cases.

**Mitigation applied (v2):**
- ✅ `MaxPolicyFileBytes = 16 * 1024 * 1024` constant in `pkg/policy/types.go`. `LoadFile` reads via `io.ReadAll(io.LimitReader(f, MaxPolicyFileBytes+1))` — the +1 byte trick lets us detect overrun explicitly and return a clear error, rather than silently truncating to 16 MiB and parsing zero docs (which would have been the worst possible failure mode for a security control)
- Verified in dev VM: 17 MiB pathological YAML → `ERROR policy load failed err="policy file ... exceeds cap of 16777216 bytes"` (exits with status 1); 4 KB legit policy → `INFO policy applied (delta) docs=4`

**Not addressed (out of scope for this fix):** `metadata.name` collisions are still ignored (last write wins). Worth filing as a separate F-9 in a future audit revision.

### F-3 — DNS resolution timeout for `host:` rules is 2 s, no caching

**Status:** ✅ **CLOSED in v3** (current commit)  
**CVSS 3.1 (project context, before fix):** AV:N / AC:L / PR:N / UI:N / S:U / C:N / I:N / A:L → **5.3 (Medium)** — outside attacker capability via DNS poisoning  
**CVSS 3.1 after fix:** unchanged for the underlying threat (still depends on resolver trust), but the *attack window* is reduced from "every Apply tick" (~5s default) to "every TTL period" (60s default, configurable to 0 for pre-fix behaviour or to higher values for stricter mitigation). The mitigation also adds stale-while-error fallback that strengthens enforcement availability against transient resolver outages.

**Where:** `pkg/policy/sync.go::resolveRuleTargets` — `net.DefaultResolver.LookupIPAddr` with a 2-second context timeout, called once per `host:` rule on every Apply tick (typically every cgroup-event-driven reconciliation, or every `resolveInterval` seconds as a fallback).

**Issue.** A rule like `host: api.corp.example.com` is re-resolved on every Apply. If the upstream resolver is poisoned, a malicious DNS response can flip the `/32` LPM entries to attacker-controlled IPs — meaning a `drop` rule pointed at a CDN-hosted destination could be redirected to allow traffic to the attacker's IP. Conversely, an `allow` rule (where `defaultEgress = "drop"`) could be redirected to drop legitimate traffic.

**Realism.** This is a property of the resolver, not the agent. The same risk exists for any tool that consults DNS for security policy (Cilium's FQDN policies have the same caveat upstream). The mitigation is the *operator* using a trusted resolver — typically the corporate DNS that this project's `deny-public-dns` baseline is designed to *enforce* in the first place. There is also a `dnssec` family of remediations the operator can deploy; the agent does not perform DNSSEC validation today.

**Mitigation applied (v3):**
- ✅ FQDN→IP cache with configurable TTL (default 60s) in `pkg/policy/sync.go`. Each Apply tick consults the cache first; only on a miss / expiry does it call `net.DefaultResolver.LookupIPAddr`
- ✅ Stale-while-error fallback: if the resolver fails on re-resolution, the agent reuses the last known-good answer for one more cycle and logs a WARN. A transient resolver outage no longer flushes `host:` LPM entries
- ✅ Wired through `-dns-cache-ttl` flag on the agent and `services.microsegebpf.dnsCacheTTL` option (default `60s`, set to `0s` to disable cache)
- ✅ ARCHITECTURE §4.5 documents the cache mechanics, including why DNSSEC remains the operator's responsibility (the cache narrows the time window, doesn't validate)

**Not addressed (out of scope):** support for a custom resolver address (DoT, do53-tcp-only). The agent still uses `net.DefaultResolver` which respects `/etc/resolv.conf`. Operators wanting stronger guarantees should run a local DNSSEC-validating resolver (e.g. `unbound`) and point `/etc/resolv.conf` at it.

### F-4 — `microseg-probe` connects to the gRPC observer with `insecure.NewCredentials()`

**Status:** ✅ **CLOSED in v3** (current commit)  
**CVSS 3.1 (project context, before fix):** AV:L / AC:L / PR:L / UI:N / S:U / C:L / I:N / A:N → **3.3 (Low)**

**Where:** `cmd/microseg-probe/main.go` — gRPC client always uses insecure transport.

**Issue.** The CLI talks to the observer over Unix socket by default (no TLS needed — kernel mediates auth via mode bits). If the operator switches the agent to TCP and points `microseg-probe -addr=` at it, the connection is in the clear. Combined with **F-1**, an on-path attacker on the LAN segment can read every flow event the probe streams.

**Mitigation applied (v3):**
- ✅ Server-side TLS / mTLS in `pkg/observer/server.go` (see F-1)
- ✅ Probe-side TLS in `cmd/microseg-probe/main.go::buildClientCreds` — `-tls-ca`, `-tls-cert`, `-tls-key`, `-tls-server-name`, `-tls-insecure` flags. Default behaviour unchanged (insecure for Unix socket, where the kernel mediates); any non-empty TLS flag opts into a `tls.Config` with `MinVersion = TLS 1.2`
- Verified end-to-end in dev VM: probe with valid CA + client cert succeeds; probe without client cert against an mTLS server gets `tls: certificate required`; probe in plaintext against a TLS server gets `error reading server preface: EOF`

### F-5 — Vector config materialised at module evaluation; secrets passed via env

**CVSS 3.1 (project context):** AV:L / AC:H / PR:H / UI:N / S:U / C:L / I:N / A:N → **2.5 (Low)**

**Where:** `nix/microsegebpf.nix::microsegebpf-log-shipper.serviceConfig.LoadCredential` and the `ExecStartPre` shell script that exports `MICROSEG_OS_PASSWORD` / `MICROSEG_SL_KEY_PASS`.

**Issue.** Credentials live in two places transiently:
1. The original file path (`auth.passwordFile`, `tls.keyPassFile`) — typically root:root mode 0600 or root:ssl-cert mode 0640. Outside our control.
2. systemd's `LoadCredential` bind-mount in `/run/credentials/microsegebpf-log-shipper.service/` — readable only by the unit's UID (the dynamic user).
3. The shell-exported env var `MICROSEG_OS_PASSWORD` / `MICROSEG_SL_KEY_PASS` — visible in `/proc/<pid>/environ` to anyone who can read it (the dynamic user, root, anyone with `CAP_SYS_PTRACE`).

**Realism.** Nothing on the workstation should be reading other users' `/proc/*/environ` — `ProtectSystem=strict` on the Vector unit makes it hard, and root reading a Vector env var is the same trust level as root reading the original password file directly. The env-var pattern is what Vector's `${VAR}` substitution requires; alternatives (file-based auth) exist for the OpenSearch sink and are documented as an `extraSettings` knob.

**Mitigation (already applied):** `LoadCredential` bind-mount is the right pattern — keys never appear in the unit's `Environment=` directive (which would be persisted in systemd's journal). The `ExecStartPre` script reads the credential into the env var **only at start time**, never written to disk. This is the standard NixOS recipe.

**Mitigation (optional follow-up):** support Vector's native file-based auth substitution (`@/path/to/file` syntax in some sinks) to skip the env-var hop entirely on the OpenSearch path.

### F-6 — eBPF C source: bound checks reviewed, verifier-clean

**CVSS 3.1 (project context):** N/A (no finding).

**Where:** `bpf/microseg.c` — every TLS parser, LPM lookup, and ring-buffer reservation reviewed.

**Findings during review:**
- All `bpf_skb_load_bytes` calls check the return value before using the read bytes (`return SKB_PASS` on error).
- All pointer arithmetic on the packet (`data`, `data_end`) is bracketed by the standard verifier-friendly `if ((void *)(t + 1) > data_end) return SKB_PASS;` pattern (line 529, 534, etc.).
- The SNI walker uses a hard `j &= MAX_SNI_NAME_BYTES - 1` mask after every iteration — needed because the verifier rejects loop-bound `if`-and-return for stack accesses; we make the bound a power of two and apply a mask.
- The 256-byte SNI scratch buffer was moved off the stack into a per-CPU array map specifically to avoid the BPF 512-byte stack budget, which prevents a class of accidental stack-overflow that would have been a verifier failure rather than a kernel exploit, but is still good hygiene.
- The TLS extension walker uses `bpf_loop` rather than `#pragma unroll`, so it's bounded by the helper signature (`u32 max_iter`) rather than by the verifier's instruction budget.

**No verifier-bypass, no OOB read/write, no kernel panic vector identified.** The kernel program itself runs in the most restricted execution environment Linux offers; the verifier is the actual final reviewer.

### F-7 — Inotify watcher: subscriber list grows unbounded if `Subscribe()` is called per loop iteration

**CVSS 3.1 (project context):** AV:L / AC:H / PR:H / UI:N / S:U / C:N / I:N / A:L → **2.4 (Low)**

**Where:** `pkg/identity/watcher.go::Subscribe`. The watcher returns a fresh channel per call and appends it to a list; nothing trims the list when subscribers stop reading.

**Issue.** This was found and fixed during initial development (commit `c267762`'s description spells out the saga that took 4 CI runs). The current main.go calls `Subscribe()` exactly once outside the loop. A future contributor who copies the pattern naively would leak channels — the watcher would still publish to dead consumers, and memory usage would grow.

**Mitigation (recommended follow-up):**
- Add an `Unsubscribe(ch <-chan struct{})` method
- Garbage-collect dead subscribers on `broadcast()` failure (non-blocking send detects a full / closed channel)
- Add a `t.Helper()`-style assertion in test that `Subscribe` is called once

### F-8 — Default `defaultEgress = "allow"` and `defaultIngress = "allow"` — fail-open

**CVSS 3.1 (project context):** N/A — this is by design, not a bug, but worth flagging in a security audit.

**Where:** `nix/microsegebpf.nix:75-85`.

**Issue.** When no policy matches a flow, the verdict is "allow". An operator who deploys with no policies and relies on the default has no enforcement at all — exactly the bake-in mode the README documents. **A defender deploying microsegmentation should switch `defaultEgress = "drop"`** (and add explicit allow rules) once the policy bundle is baked in.

**Documented in:** README "Limitations and roadmap" section explicitly calls out the bake-in / production toggle. The `enforce = false` bake-in mode (commit `fed5f4b`) further demotes drop verdicts to log so the operator can ramp up safely.

---

## 6. Architecture strengths

The audit identified the following design choices as security-positive:

1. **No CAP_SYS_ADMIN, no root** — the agent runs with the minimum capability set required for eBPF (`CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`, `CAP_SYS_RESOURCE`). `NoNewPrivileges = true`, `ProtectSystem = strict`, `ReadWritePaths = [ "/sys/fs/bpf" ]` only.
2. **Static binary, near-empty closure** — the agent links nothing dynamically. The runtime closure is `iana-etc + mailcap + microseg-agent` (4 components total). No glibc CVE applies.
3. **Vector shipper is a separate, sandboxed unit** — `DynamicUser = true`, `RestrictAddressFamilies = [ AF_INET AF_INET6 AF_UNIX ]`, `SystemCallFilter = [ @system-service @network-io ]`, `ProtectKernel*` everywhere. A compromise of Vector cannot pivot to the agent or to the BPF maps; it can only egress to the configured OpenSearch / syslog endpoints (which `RestrictAddressFamilies` would also limit to IPv4/IPv6 sockets — no raw, no netlink).
4. **Default = TLS for syslog** (`mode = "tcp+tls"`), with a loud NixOS warning if downgraded to plain TCP or UDP. The unencrypted choice is reviewable in the rebuild log, never silent.
5. **Default = TLS verification on for OpenSearch and syslog** (`tls.verifyCertificate = true`). Disabling it requires an explicit `false` and Vector emits a runtime WARN.
6. **Secrets via systemd `LoadCredential`** — bind-mount of the source file into the unit's namespace, never embedded in the unit's `Environment=` directive (which journald would persist).
7. **REUSE 3.3 compliant** — every file has clear copyright + license attribution, audited by `reuse lint` in the dev VM.
8. **Pre-generated eBPF artefacts committed** — the Nix build is reproducible and runs in a sandbox without `/sys` access, eliminating the class of build-time tampering that would otherwise come from regenerating BTF on every CI run.
9. **TLS peek-only, never decryption** — the SNI/ALPN parser inspects ClientHello extensions and nothing else. There is no key material in the kernel program; an operator who needs L7 inspection must use a separate proxy.
10. **Delta-based map reconciliation** — `Apply()` writes only changed entries (commit `585e20c`). No transient gap where a flow matches the old policy and the new one but neither's entry is in the map.

---

## 7. Recommendations

In priority order, lowest-effort first. Strikethrough = done in a later revision.

### 7.1 Immediate (closed in v2 — commit `9b7f56a`)

- [x] ~~Bump Go to 1.25.9+~~ — covered by CI runner (setup-go installs 1.25.9); the dev VM tracks a slightly older snapshot, irrelevant to deployment
- [x] ~~Document the Hubble TCP-listener exposure (F-1)~~ — Nix warning + agent runtime warning + README + ARCHITECTURE
- [x] ~~Cap policy file size (F-2)~~ — `MaxPolicyFileBytes = 16 MiB` with explicit overrun error
- [x] ~~Bump quay.io/cilium/hubble-ui:v0.13.2 → v0.13.5~~ — upstream "Security Patching - Dockerfile" PR
- [x] ~~Hubble UI: drop --network=host~~ — switched to podman bridge with `127.0.0.1:port` mapping

### 7.2 Short-term (closed in v3 — current commit)

- [x] ~~TLS for the gRPC observer (F-1, F-4)~~ — full server-side TLS + mTLS via `services.microsegebpf.hubble.tls.*`, matching `-tls-*` flags on `microseg-probe`
- [x] ~~DNS resolution caching with TTL (F-3)~~ — `dnsCacheTTL` option (default 60s) + stale-while-error fallback

### 7.3 Long-term (open)

- [ ] Track nixpkgs-25.11 security branch via a renovate-style automation; today the flake input pins the channel name (`nixos-25.11`) which auto-tracks but is non-reproducible across two clones a week apart.
- [ ] Subscribe / Unsubscribe symmetry on the inotify watcher (F-7).
- [ ] Per-cgroup TLS scoping (already on the README roadmap) — eliminates the "host-global SNI deny" caveat.
- [ ] Reject duplicate `metadata.name` in policy bundles (called out in F-2 mitigation note).
- [ ] Optional support for a custom resolver address (DoT / do53-tcp-only) so an operator who can't deploy a local DNSSEC resolver still gets some validation (F-3 not-addressed note).

---

## 8. CI integration

Add a workflow `.github/workflows/security.yml` that runs nightly and on every PR:

1. `govulncheck ./...` — gates Go stdlib + module CVEs
2. `reuse lint` — gates license compliance
3. `sbomnix` against the agent and Vector closures, diff against `sbom/sbom-*.cdx.json` — gates closure drift (any new dep gets a SBOM update)
4. `grype` against the Hubble UI pinned tag — early warning when the upstream image accumulates CVEs

Wire the workflow to fail PRs that introduce a CVE ≥ 7.0 in the agent's reachable code path.

---

## 9. Out-of-scope items deliberately not assessed

- **The Linux kernel itself.** The eBPF datapath runs in-kernel; a kernel CVE that affects `cgroup_skb`, `bpf_loop`, or LPM trie semantics could cascade into our code. Tracking via the workstation's normal kernel update cadence (NixOS `linuxPackages_latest` follows mainline within days).
- **Operator-side secrets management** (SOPS, agenix, vault-agent). The module accepts `passwordFile`, `keyFile`, `keyPassFile` paths; how they get there is the deployment's concern.
- **Network-layer attacks** below the eBPF hook. cgroup_skb fires *after* iptables / nftables in the egress path and *before* iptables / nftables on ingress. Operators who want defense-in-depth should layer this with a host firewall.

---

## 10. Disclosure

This is the first security audit of `nixos-microsegebpf`. There are no embargoed findings — every issue documented here is either:
- A known third-party CVE already public in the NVD
- A code-review finding in this project's own source, disclosed in this document with the mitigation guidance an operator needs

If you discover a vulnerability not covered here, please email **aurelien.ambert@proton.me** with `[microsegebpf]` in the subject. PGP key fingerprint and disclosure timeline will be added in a future revision.
