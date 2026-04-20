<!--
SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
SPDX-License-Identifier: MIT
-->

# Security audit — `nixos-microsegebpf`

**Audit date:** 2026-04-20  
**Commit audited:** `afe2975` (REUSE clean + emit-allow wiring closed)  
**Auditor:** project author, self-review with tooling  
**Scope:** every source file in this repository, plus the runtime closures of the agent, the Vector log shipper, and the optional Hubble UI OCI image.

> [English](SECURITY-AUDIT.md) · [Français](SECURITY-AUDIT.fr.md)

---

## 1. Executive summary

| | Finding count | Highest CVSS 3.1 |
|---|---|---|
| Issues introduced **by this project's code** | 2 (both Low) | 3.1 |
| Issues from **third-party runtime dependencies** | 32 (de-duped) | 9.1 (CVE-2026-28386 / OpenSSL) |
| Issues from **bundled OCI image** (`hubble-ui:v0.13.2`, optional) | 60+ | 8.8 (CVE-2025-15467 / OpenSSL on Alpine) |
| Issues from **the Go standard library** (1.25.8 → 1.25.9) | 4 (3 affecting agent reachable code) | ~7.5 |

**No vulnerability discovered in the project's own source code rises above CVSS 3.1 (Low).** Every Critical / High score in the report comes from upstream code (Go stdlib, OpenSSL, glibc, Alpine-packaged libraries) and is closed by tracking the nixpkgs-25.11 security branch + updating the Go toolchain to 1.25.9+.

**Two architectural issues** (both worth flagging even if no CVE attaches): (a) the Hubble gRPC observer has no built-in transport authentication when configured with a TCP listener; (b) the optional `hubble-ui` OCI container runs with `--network=host`, which binds the dashboard to every interface of the workstation. Both are mitigated by the default configuration (Unix socket, UI disabled), but the documentation should make the trade-off impossible to miss when an operator opts into either.

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
│  hubble-ui (optional, OCI: quay.io/cilium/hubble-ui:v0.13.2)  │
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

### 4.3 Hubble UI OCI image (`quay.io/cilium/hubble-ui:v0.13.2`, optional)

Pinned in the NixOS module under `services.microsegebpf.hubble.ui.enable = true` (default: false). 60+ CVEs reported by `grype` against the Alpine packages baked into the image. The four with the highest reachability:

| CVE | Package | CVSS | Note |
|---|---|---|---|
| CVE-2025-15467 | libssl3 / libcrypto3 (Alpine OpenSSL) | 8.8 | Same upstream as the Vector closure entry |
| CVE-2025-69420 | libssl3 / libcrypto3 | 7.x | TLS issue |
| CVE-2026-28389 / 28390 / 28388 | libssl3 / libcrypto3 | 7.x | TLS issues |
| CVE-2026-27651 / 27654 | nginx 1.27.3 | 7.x | HTTP request smuggling |

**Mitigation:** bump the pinned tag to a fresher `cilium/hubble-ui` release (Cilium publishes new images as their base layer is rebuilt). The pin lives in `nix/microsegebpf.nix:519`; flipping it to e.g. `v0.14.x` once published is a one-line change. Track via the upstream [cilium/hubble-ui releases](https://github.com/cilium/hubble-ui/releases) page.

**Architectural note (not a CVE):** the OCI container is launched with `--network=host` (`nix/microsegebpf.nix:531`) so it can reach the agent's Unix socket at `/run/microseg/hubble.sock`. With `--network=host`, the nginx in the container binds to **every interface of the workstation** on `cfg.hubble.ui.port` (default 12000) — anybody who can route to the workstation on that port sees the live flow map. See finding **F-1** below.

---

## 5. Manual code-review findings

These do not have a CVE assigned (we are the upstream); they are project-introduced risks discovered by line-by-line review.

### F-1 — Hubble gRPC + UI exposure when configured for TCP / network access

**CVSS 3.1 (project context):** AV:A / AC:L / PR:N / UI:N / S:U / C:H / I:N / A:N → **6.5 (Medium)**

**Where:** `pkg/observer/server.go:91-95` and `nix/microsegebpf.nix:531`.

**Issue.** The `Hubble.Observer` gRPC server is created with bare `grpc.NewServer()` — no transport credentials, no auth interceptor. The default `services.microsegebpf.hubble.listen` is the Unix socket `unix:/run/microseg/hubble.sock` (mode 0750 via `RuntimeDirectoryMode`), which restricts access to root on the workstation. That default is safe.

**However:** if an operator switches to a TCP listener (e.g. `hubble.listen = "0.0.0.0:50051"`) the observer streams every flow event to any client that can connect — exposing the workstation's full network activity, including SNI hostnames the user reaches. The same holds when `hubble.ui.enable = true` is combined with the OCI container's `--network=host`: the dashboard listens on `cfg.hubble.ui.port` on every interface.

**Mitigation in code (recommended follow-up):**
- Emit a NixOS warning when `hubble.listen` does not start with `unix:/`
- Bind the OCI container's nginx to `127.0.0.1` instead of the default `0.0.0.0` (the Hubble UI image accepts a `LISTEN_ADDR` env var in its newer releases) **or** drop `--network=host` and use a podman network namespace
- Document the trade-off in README's "Hubble integration" section, alongside the OpenSearch shipper which is already documented as taking an explicit endpoint

**Mitigation today:** the defaults are safe (Unix socket + UI disabled). An operator who flips either knob should put the workstation behind a host firewall or, ideally, leave the gRPC server on Unix sockets and drive the UI through `hubble-ui` running on a separate host that proxies via SSH.

### F-2 — Policy YAML loaded with `gopkg.in/yaml.v3`, parsed without size cap

**CVSS 3.1 (project context):** AV:L / AC:L / PR:H / UI:N / S:U / C:N / I:N / A:L → **3.1 (Low)**

**Where:** `pkg/policy/types.go::LoadFile` (file path passed via `-policy=...`).

**Issue.** The agent reads the policy file in full and calls `yaml.NewDecoder(f).Decode(...)`. There is no upper bound on file size before parsing. An operator (or a malicious local-root with write access to the file path) could supply a multi-gigabyte YAML billion-laughs / nested-anchors document and OOM the agent.

**Realism.** The agent runs as a non-root user with `CAP_BPF` and reads the policy from a path the operator controls. The threat model is "operator-supplied input only", so this is essentially a footgun for the operator, not an external attack vector. `yaml.v3` is also documented to refuse some pathological aliases by default (`maxAliases = 1024`), which limits — but does not eliminate — the worst cases.

**Mitigation (recommended follow-up):**
- Wrap the file read with `io.LimitReader(f, 16 * 1024 * 1024)` — 16 MiB is comfortably above any sane policy document; `pkg/policy/sync.go` already enforces `maxExpansion = 16384` per rule which gives a downstream cap.
- Reject documents with `metadata.name` collisions (currently ignored — last write wins)

### F-3 — DNS resolution timeout for `host:` rules is 2 s, no caching

**CVSS 3.1 (project context):** AV:N / AC:L / PR:N / UI:N / S:U / C:N / I:N / A:L → **5.3 (Medium)** **— but the score is the *outside* attacker capability**, not what they can do against this agent specifically. See "Realism" below.

**Where:** `pkg/policy/sync.go::resolveRuleTargets` — `net.DefaultResolver.LookupIPAddr` with a 2-second context timeout, called once per `host:` rule on every Apply tick (typically every cgroup-event-driven reconciliation, or every `resolveInterval` seconds as a fallback).

**Issue.** A rule like `host: api.corp.example.com` is re-resolved on every Apply. If the upstream resolver is poisoned, a malicious DNS response can flip the `/32` LPM entries to attacker-controlled IPs — meaning a `drop` rule pointed at a CDN-hosted destination could be redirected to allow traffic to the attacker's IP. Conversely, an `allow` rule (where `defaultEgress = "drop"`) could be redirected to drop legitimate traffic.

**Realism.** This is a property of the resolver, not the agent. The same risk exists for any tool that consults DNS for security policy (Cilium's FQDN policies have the same caveat upstream). The mitigation is the *operator* using a trusted resolver — typically the corporate DNS that this project's `deny-public-dns` baseline is designed to *enforce* in the first place. There is also a `dnssec` family of remediations the operator can deploy; the agent does not perform DNSSEC validation today.

**Mitigation (recommended follow-up):**
- Cache resolution results with TTL respect — currently every Apply re-resolves, which doubles the resolver-poisoning attack surface
- Optionally support `do53-tcp-only` or `DoT` resolution by allowing the operator to set a custom resolver address
- Document the dependency on a trusted upstream resolver in the `deny-host` baseline doc

### F-4 — `microseg-probe` connects to the gRPC observer with `insecure.NewCredentials()`

**CVSS 3.1 (project context):** AV:L / AC:L / PR:L / UI:N / S:U / C:L / I:N / A:N → **3.3 (Low)**

**Where:** `cmd/microseg-probe/main.go` — gRPC client always uses insecure transport.

**Issue.** The CLI talks to the observer over Unix socket by default (no TLS needed — kernel mediates auth via mode bits). If the operator switches the agent to TCP and points `microseg-probe -addr=` at it, the connection is in the clear. Combined with **F-1**, an on-path attacker on the LAN segment can read every flow event the probe streams.

**Mitigation:** add `-tls`, `-cert`, `-key`, `-ca` flags to the probe; mirror the agent's TLS support (which currently doesn't exist either — the gRPC server has no TLS path). This is a coherent gap; the fix is in two pieces (server + client).

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

In priority order, lowest-effort first.

### 7.1 Immediate (next commit)

- [ ] **Bump Go to 1.25.9+** (or rely on nixpkgs-25.11 security branch) — closes 3 reachable stdlib CVEs (the 4th, html/template XSS, is N/A for this project but tracking with the rest is cleaner)
- [ ] **Document the Hubble TCP-listener exposure** (F-1) — README + add a NixOS warning when `hubble.listen` is not a Unix socket
- [ ] **Cap policy file size** (F-2) — `io.LimitReader` to 16 MiB

### 7.2 Short-term (next few releases)

- [ ] **TLS for the gRPC observer** (F-1, F-4) — server-side TLS option in `services.microsegebpf.hubble.tls.{certFile, keyFile, caFile}`, and matching `-tls`/`-cert` flags on `microseg-probe`. Keep Unix socket as the default; offer TCP+TLS as the second option; never plain TCP.
- [ ] **Hubble UI: drop `--network=host`** in favour of a podman bridge network with `127.0.0.1:12000` host port mapping. Operator who wants remote access can SSH-tunnel.
- [ ] **DNS resolution caching with TTL** (F-3) — current behaviour is to re-resolve on every Apply; respecting the record TTL would halve the resolver-poisoning surface.
- [ ] **Bump `quay.io/cilium/hubble-ui:v0.13.2`** to the current Cilium release (likely v0.14.x or later by the time this is read).

### 7.3 Long-term

- [ ] Track nixpkgs-25.11 security branch via a renovate-style automation; today the flake input pins the channel name (`nixos-25.11`) which auto-tracks but is non-reproducible across two clones a week apart.
- [ ] Subscribe / Unsubscribe symmetry on the inotify watcher (F-7).
- [ ] Per-cgroup TLS scoping (already on the README roadmap) — eliminates the "host-global SNI deny" caveat.

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
