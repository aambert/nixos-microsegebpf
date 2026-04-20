# SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
# SPDX-License-Identifier: MIT
#
# Top-level entry point: `nix-build` produces the agent binary.
# Module consumers should import `nix/microsegebpf.nix` directly.
{
  pkgs ? import (builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/nixos-25.11.tar.gz";
  }) { },
}:
pkgs.callPackage ./nix/package.nix {
  # CO-RE / BTF source: use the latest mainline kernel headers from
  # nixpkgs by default. NixOS module callers override with the actual
  # running kernel via `config.boot.kernelPackages.kernel`.
  kernel = pkgs.linuxPackages_latest.kernel;
}
