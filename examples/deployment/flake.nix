# SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
# SPDX-License-Identifier: MIT
#
# Example deployment flake — copy this into your own infra repo and
# adapt. Demonstrates the GitOps pattern this project is built for:
#
#   - one git repo holds the NixOS config for the workstation
#   - microsegebpf comes in as a flake input, version-pinned in
#     flake.lock
#   - policies are expressed in Nix and reviewed via PR like the rest
#     of the configuration
#   - CI (your existing pipeline) runs `nix flake check` and then
#     `nixos-rebuild switch --flake .#workstation` on the target,
#     either over SSH or via deploy-rs / colmena / morph
#
# `nix flake check` here exercises microsegebpf's own VM test, so a
# bad policy fails CI before it ever reaches the workstation.
{
  description = "Example workstation deployment consuming nixos-microsegebpf";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    microsegebpf = {
      url = "github:aambert/nixos-microsegebpf";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      microsegebpf,
    }:
    {
      nixosConfigurations.workstation = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          microsegebpf.nixosModules.default
          (
            { config, pkgs, ... }:
            {
              # Standard workstation config goes here (boot, fs,
              # users, ...) — elided for brevity.

              services.microsegebpf = {
                enable = true;

                # Two-week observe-only bake-in before flipping to
                # enforcement. Hubble UI surfaces every flow during
                # this window so the operator can spot legitimate
                # traffic that would be dropped.
                enforce = false;
                emitAllowEvents = true;

                policies =
                  with microsegebpf.lib.policies.baselines;
                  [
                    # Block direct egress to public DNS resolvers from
                    # the user session — forces resolution through the
                    # corporate resolver.
                    (deny-public-dns { })

                    # Restrict inbound SSH to the corporate bastion only.
                    (sshd-restrict { allowFrom = "10.0.0.0/24"; })

                    # Hard block on RFC1918 lateral movement from any
                    # browser / mail client running under the user
                    # session.
                    (deny-rfc1918-from-user-session { })
                  ]
                  ++ [
                    # One-off custom rule using the low-level helper.
                    (microsegebpf.lib.policies.mkPolicy {
                      name = "deny-cryptominer-pools";
                      selector = { cgroupPath = "/"; };
                      egress = map
                        (cidr: microsegebpf.lib.policies.drop {
                          inherit cidr;
                          ports = [ "3333" "4444" "5555" "8888" "14444" ];
                          protocol = "tcp";
                        })
                        [
                          # Replace with feed-generated list at deploy time.
                          "203.0.113.10/32"
                        ];
                    })
                  ];

                hubble.ui.enable = true;
              };
            }
          )
        ];
      };

      # Re-export microsegebpf's checks so this flake's `nix flake
      # check` runs them too. CI will fail on any policy that breaks
      # the VM test.
      checks.x86_64-linux = microsegebpf.checks.x86_64-linux;
    };
}
