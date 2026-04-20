# SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
# SPDX-License-Identifier: MIT
#
# Build derivation for the microseg-agent binary.
#
# Two-stage build: bpf2go runs in a `preBuild` hook to compile the eBPF
# C source into bytecode + Go bindings (committed-out at the source
# level so this stays reproducible), then the standard buildGoModule
# path produces the agent binary.
#
# vmlinux.h is generated from `linuxPackages.kernel.dev` so the BTF
# baked into the produced object matches the kernel that will load it.
# A NixOS module is the natural caller; ad-hoc users should pass
# `kernel = pkgs.linuxPackages_latest.kernel` to mirror their host.
{
  lib,
  buildGoModule,
  clang,
  llvm,
  bpftools,
  pkg-config,
  kernel ? null,
}:
buildGoModule rec {
  pname = "microseg-agent";
  version = "0.1.0";

  src = ../.;

  # Recompute when go.mod changes:
  #   nix-build 2>&1 | grep "got:" | awk '{print $2}'
  # then paste the result here.
  vendorHash = "sha256-bQnaYCWEjaAK0YfgsgY67xwscTfxwZjAn5Y3LZp7k/4=";

  nativeBuildInputs = [
    clang
    llvm
    bpftools
    pkg-config
  ];

  # Disable cc-wrapper hardening (clang on bpfel target rejects it).
  hardeningDisable = [ "all" ];

  # The goModules derivation only needs go.{mod,sum} to vendor — it
  # does NOT need clang/bpftool/BTF. Strip the preBuild from that
  # intermediate derivation; it's only relevant for the final binary.
  # We leave nativeBuildInputs alone so buildGoModule's own Go toolchain
  # stays in scope.
  overrideModAttrs = (_: {
    preBuild = "";
  });

  # Use pre-generated bpf2go output (microseg_bpfel.{go,o} +
  # vmlinux.h) when present in the source tree. They're produced by
  # `make generate` outside the Nix sandbox (Nix has no access to
  # /sys/kernel/btf/vmlinux). If absent, regenerate on-the-fly using
  # the BTF from the runtime kernel — only works when the build is
  # run with `--option sandbox false`.
  preBuild =
    let
      kernelPath = if kernel != null then "${kernel}/vmlinux" else "";
    in
    ''
      if [ ! -f bpf/microseg_bpfel.o ] || [ ! -f bpf/microseg_bpfel.go ]; then
        echo "Pre-generated BPF artefacts missing; trying to regenerate..."
        if [ ! -f bpf/vmlinux.h ]; then
          if [ -n "${kernelPath}" ] && [ -f "${kernelPath}" ]; then
            bpftool btf dump file ${kernelPath} format c > bpf/vmlinux.h
          elif [ -f /sys/kernel/btf/vmlinux ]; then
            bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
          else
            echo "ERROR: no BTF source for vmlinux.h." >&2
            echo "Run 'make generate' on a host with /sys/kernel/btf/vmlinux first," >&2
            echo "then commit bpf/microseg_bpfel.{go,o} + bpf/vmlinux.h before nix-build." >&2
            exit 1
          fi
        fi
        (cd bpf && go generate ./...)
      else
        echo "Using pre-generated BPF artefacts."
      fi
    '';

  subPackages = [ "cmd/microseg-agent" ];

  env.CGO_ENABLED = "0";

  meta = with lib; {
    description = "Cilium-style microsegmentation agent for Linux workstations (eBPF cgroup-skb + Hubble observer)";
    homepage = "https://github.com/aambert/nixos-microsegebpf";
    license = licenses.mit;
    platforms = platforms.linux;
    mainProgram = "microseg-agent";
  };
}
