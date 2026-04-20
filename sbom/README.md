<!--
SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
SPDX-License-Identifier: MIT
-->

# Software Bill of Materials

Generated artefacts for [`SECURITY-AUDIT.md`](../SECURITY-AUDIT.md). All
files are CycloneDX 1.5 JSON, SPDX 2.3 JSON, or flat CSV — pick the
format your asset-management / vulnerability-scanning tool ingests.

| File | Format | Subject |
|---|---|---|
| `sbom-go.cdx.json` | CycloneDX 1.5 | Direct Go module dependencies (`cyclonedx-gomod mod`) |
| `sbom-source.cdx.json` | CycloneDX 1.5 | Full source-tree scan (`syft scan dir:.`) |
| `sbom-source.spdx.json` | SPDX 2.3 | Same, SPDX format |
| `sbom-closure.cdx.json` | CycloneDX 1.5 | `microseg-agent` Nix runtime closure (`sbomnix`) |
| `sbom-closure.spdx.json` | SPDX 2.3 | Same |
| `sbom-closure.csv` | CSV | Same, flat |
| `sbom-vector.cdx.json` | CycloneDX 1.5 | Vector 0.51.1 Nix runtime closure (`sbomnix`) |
| `sbom-vector.csv` | CSV | Same, flat |

## Regenerating

In the dev VM (which has Nix + the tools available):

```sh
cd /root/nixos-microsegebpf

# 1. Source-tree SBOMs (no build required)
syft scan dir:. -o cyclonedx-json=sbom/sbom-source.cdx.json
syft scan dir:. -o spdx-json=sbom/sbom-source.spdx.json

# 2. Go module SBOM (requires `go` in PATH — use the dev shell)
nix-shell --run 'cyclonedx-gomod mod -json -output sbom/sbom-go.cdx.json .'

# 3. Closure SBOMs with vulnerability scan (requires a built closure)
AGENT=$(nix-build --no-out-link)
sbomnix $AGENT --include-vulns \
  --cdx  sbom/sbom-closure.cdx.json \
  --spdx sbom/sbom-closure.spdx.json \
  --csv  sbom/sbom-closure.csv

VECTOR=$(nix-build '<nixpkgs>' -A vector --no-out-link)
sbomnix $VECTOR --include-vulns \
  --cdx sbom/sbom-vector.cdx.json \
  --csv sbom/sbom-vector.csv
```

## Why three formats?

Different consumers want different things:

- **CycloneDX 1.5 JSON** — OWASP Dependency-Track, Sonatype Nexus IQ,
  GitHub Dependabot ingest this natively. Carries vulnerability data
  alongside the components when scanned with `--include-vulns`.
- **SPDX 2.3 JSON** — the historical standard, mandated by some
  procurement / supply-chain compliance frameworks (US Executive
  Order 14028, NTIA minimum elements). Works with FOSSology and
  similar.
- **CSV** — for the human or spreadsheet that just wants a flat
  list of `(name, version, store_path, CPE)` to grep.

## Coverage notes

- The agent's runtime closure has only 4 components (it's a static Go
  binary; no glibc, no openssl). The interesting vulnerability surface
  is in **Vector**, which is a separate process we ship as the log
  shipper.
- The Hubble UI OCI image (`quay.io/cilium/hubble-ui:v0.13.2`) is NOT
  in these SBOMs because it's pulled at runtime by podman, not built
  by Nix. Scan it directly with `grype quay.io/cilium/hubble-ui:v0.13.2`
  — see SECURITY-AUDIT.md §4.3.
- These SBOMs reflect the closures produced by the nixpkgs commit
  pinned in `flake.lock` at the time of generation. A consumer who
  pins a different nixpkgs commit will get a different closure with
  potentially different CVE exposure — re-scan after every
  `nix flake update`.
