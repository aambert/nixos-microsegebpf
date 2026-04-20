# SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
# SPDX-License-Identifier: MIT
#
# Reproducible build environment for nixos-microsegebpf.
#
# Two consumption modes:
#
#   1. From the flake (`nix develop`): the flake passes its already-
#      resolved `pkgs` so we don't refetch nixpkgs. This is required
#      for pure evaluation mode.
#
#   2. From plain `nix-shell` (no flakes): we fall back to fetching a
#      pinned nixpkgs tarball. The sha256 is intentionally left
#      unpinned here — `nix-shell` runs in impure mode where this is
#      legal, and we don't want to babysit hash bumps for the
#      non-flake path.
{
  pkgs ? import (builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/nixos-25.11.tar.gz";
  }) { },
}:
pkgs.mkShell {
  # Disable cc-wrapper hardening flags: they inject options like
  # -fzero-call-used-regs and -fstack-protector that clang refuses (or
  # silently drops with a warning) when the target is `bpfel`. Letting
  # them through breaks bpf2go.
  hardeningDisable = [ "all" ];

  packages = with pkgs; [
    go_1_25
    clang
    llvm
    bpftools          # bpftool for live introspection
    libbpf
    linuxHeaders
    pkg-config
    rsync
    protobuf
    protoc-gen-go
    protoc-gen-go-grpc
  ];

  shellHook = ''
    # cilium/ebpf is pure Go: leave CGO off so `go build` ignores
    # microseg.c (otherwise the build refuses .c files in a non-cgo
    # package).
    export CGO_ENABLED=0
    # bpf2go invokes clang directly — make sure the system one wins.
    export PATH=${pkgs.clang}/bin:${pkgs.llvm}/bin:$PATH
    echo "nixos-microsegebpf dev shell — kernel: $(uname -r), go: $(go version | awk '{print $3}')"
  '';
}
