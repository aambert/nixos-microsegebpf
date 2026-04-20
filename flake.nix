# SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
# SPDX-License-Identifier: MIT
#
# Flake entrypoint for nixos-microsegebpf.
#
# Outputs (all systems):
#   packages.default            — the microseg-agent binary (BPF + Go)
#   packages.microseg-probe     — the headless Hubble client
#   devShells.default           — Go 1.25 + clang 21 + bpftool + protobuf
#   checks.vm-test              — nixosTest: boots a VM, applies a drop
#                                 policy, asserts that the in-kernel
#                                 datapath blocks the matching flow
#
# Outputs (system-agnostic):
#   nixosModules.default        — services.microsegebpf
#   lib.policies                — composable policy baselines
#                                 (mkPolicy + a curated set of
#                                 deny-public-dns, sshd-restrict, ...)
#
# Consume from a deployment flake:
#
#   {
#     inputs.microsegebpf.url = "github:aambert/nixos-microsegebpf";
#     outputs = { self, nixpkgs, microsegebpf, ... }: {
#       nixosConfigurations.workstation = nixpkgs.lib.nixosSystem {
#         system = "x86_64-linux";
#         modules = [
#           microsegebpf.nixosModules.default
#           ({ ... }: {
#             services.microsegebpf = {
#               enable = true;
#               policies = with microsegebpf.lib.policies; [
#                 (baselines.deny-public-dns {})
#                 (baselines.sshd-restrict { allowFrom = "10.0.0.0/24"; })
#               ];
#             };
#           })
#         ];
#       };
#     };
#   }
{
  description = "eBPF microsegmentation for Linux workstations, with Hubble-compatible observability";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    let
      # Per-system outputs: packages, devShells, checks. Linux only —
      # the agent loads eBPF and there's no point trying on Darwin.
      perSystem = flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          packages = {
            default = pkgs.callPackage ./nix/package.nix {
              kernel = pkgs.linuxPackages_latest.kernel;
            };
          };

          devShells.default = import ./shell.nix { inherit pkgs; };

          # `nix flake check` runs every entry in `checks`. The vm-test
          # boots a NixOS VM, applies a policy, and asserts the
          # datapath actually drops the matched traffic. This is the
          # gate CI must clear before any production deployment.
          checks.vm-test = pkgs.callPackage ./nix/tests/vm-test.nix {
            module = self.nixosModules.default;
            policies = self.lib.policies;
          };
        }
      );

      # System-agnostic outputs: the NixOS module and the policy
      # composition library. They're pure Nix and don't reference any
      # platform-specific package, so they live outside the per-system
      # block and can be consumed from any flake.
      systemAgnostic = {
        nixosModules.default = import ./nix/microsegebpf.nix;
        lib.policies = import ./nix/policies { inherit (nixpkgs) lib; };
      };
    in
    perSystem // systemAgnostic;
}
