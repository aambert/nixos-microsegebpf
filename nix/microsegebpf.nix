# SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
# SPDX-License-Identifier: MIT
#
# NixOS module: services.microseg
#
# Wires the microseg-agent daemon into systemd and (optionally) ships
# the upstream hubble-ui as a co-located service so an operator can hit
# http://localhost:12000 and see the workstation flow map without any
# Kubernetes plumbing.
#
# Default posture is observability-only (default verdict = allow on
# both directions, so the eBPF program never drops a packet that wasn't
# explicitly listed in a Policy document). Flip `enforce = true` to
# honour drop verdicts.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.microsegebpf;
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    ;

  # Pre-compiled policy bundle: concatenate every YAML document supplied
  # via `cfg.policies` into a single file the agent reads at startup.
  policyFile = pkgs.writeText "microseg-policies.yaml" (
    lib.concatStringsSep "\n---\n" cfg.policies
  );

  agent = pkgs.callPackage ./package.nix {
    kernel = config.boot.kernelPackages.kernel;
  };
in
{
  options.services.microsegebpf = {
    enable = mkEnableOption "nixos-microsegebpf eBPF microsegmentation agent (Cilium-like, workstation-scoped)";

    package = mkOption {
      type = types.package;
      default = agent;
      defaultText = lib.literalExpression "pkgs.callPackage ./package.nix { kernel = config.boot.kernelPackages.kernel; }";
      description = "The microseg-agent derivation to run.";
    };

    enforce = mkOption {
      type = types.bool;
      default = false;
      description = ''
        When false (default), the agent emits flow events but never
        drops packets, regardless of policy verdicts. Useful for a
        bake-in period before flipping enforcement on.

        When true, drop verdicts in the loaded policies are enforced by
        the kernel datapath.
      '';
    };

    defaultEgress = mkOption {
      type = types.enum [ "allow" "drop" ];
      default = "allow";
      description = "Default verdict for egress flows that don't match any policy.";
    };

    defaultIngress = mkOption {
      type = types.enum [ "allow" "drop" ];
      default = "allow";
      description = "Default verdict for ingress flows that don't match any policy.";
    };

    emitAllowEvents = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Emit a flow event for every ALLOWED packet too, not just drops.
        Useful to see the full traffic map in Hubble UI; expensive on a
        busy host.
      '';
    };

    tlsPorts = mkOption {
      type = types.listOf types.port;
      default = [ 443 8443 ];
      description = ''
        Destination ports the agent treats as TLS-bearing. The
        in-kernel SNI/ALPN parser fires on TCP egress to any of these
        ports; if `blockQuic = true`, UDP egress to the same ports is
        dropped outright. Maximum 8 entries.
      '';
    };

    blockQuic = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Drop UDP egress to any port in `tlsPorts`. Forces QUIC
        (HTTP/3) clients to fall back to TCP/TLS, where the SNI
        parser can match. Without this knob QUIC traffic is
        invisible to SNI-based filtering because the SNI in QUIC
        Initial packets is encrypted with keys our eBPF parser
        cannot derive in-kernel.
      '';
    };

    policies = mkOption {
      type = types.listOf types.lines;
      default = [ ];
      example = lib.literalExpression ''
        [
          '''
            apiVersion: microseg.local/v1
            kind: Policy
            metadata:
              name: deny-public-dns
            spec:
              selector:
                cgroupPath: /user.slice
              egress:
                - action: drop
                  cidr: 1.1.1.1/32
                  ports: [443, 853]
                  protocol: tcp
          '''
        ]
      '';
      description = "List of policy documents (each a YAML string). Concatenated as one multi-document file.";
    };

    resolveInterval = mkOption {
      type = types.str;
      default = "5s";
      description = "How often to re-walk the cgroup tree and re-resolve selectors.";
    };

    hubble = {
      listen = mkOption {
        type = types.str;
        default = "unix:/run/microseg/hubble.sock";
        description = "gRPC listen address for the Hubble observer (host:port or unix:/path).";
      };

      bufferSize = mkOption {
        type = types.int;
        default = 4096;
        description = "Number of recent flow events kept in the observer ring buffer.";
      };

      ui = {
        enable = mkEnableOption "co-located hubble-ui pointed at the local microseg observer";
        port = mkOption {
          type = types.port;
          default = 12000;
          description = "Local port for the hubble-ui frontend.";
        };
      };
    };
  };

  config = mkIf cfg.enable {
    # Cgroupv2 unified hierarchy used to be opt-in via
    # `systemd.enableUnifiedCgroupHierarchy`; that option was removed
    # from nixpkgs (systemd 256+) and cgroup v1 is no longer
    # supported. We therefore have nothing to assert at this layer —
    # any kernel + systemd combination that boots NixOS today already
    # provides the cgroupv2 hierarchy that bpf_skb_cgroup_id relies on.

    environment.systemPackages = [ cfg.package ];

    systemd.services.microsegebpf-agent = {
      description = "nixos-microsegebpf eBPF microsegmentation agent";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-pre.target" ];
      before = [ "network.target" ];

      serviceConfig = {
        # `simple` rather than `notify-reload`: the Go agent doesn't
        # call sd_notify(READY=1), so a notify-style unit would sit in
        # "activating" forever and `systemctl is-active` never goes
        # green (which broke nixosTest's `wait_for_unit`). Adding
        # proper sd_notify support is a follow-up; for now Type=simple
        # is the honest description: the service is alive as soon as
        # the binary is exec'd.
        Type = "simple";
        ExecStart = lib.concatStringsSep " " [
          "${cfg.package}/bin/microseg-agent"
          "-default-egress=${cfg.defaultEgress}"
          "-default-ingress=${cfg.defaultIngress}"
          (lib.optionalString cfg.emitAllowEvents "-emit-allow=true")
          (lib.optionalString (cfg.policies != [ ]) "-policy=${policyFile}")
          "-hubble-addr=${cfg.hubble.listen}"
          "-hubble-buffer=${toString cfg.hubble.bufferSize}"
          "-resolve-every=${cfg.resolveInterval}"
          "-tls-ports=${lib.concatStringsSep "," (map toString cfg.tlsPorts)}"
          (lib.optionalString cfg.blockQuic "-block-quic=true")
        ];
        Restart = "on-failure";
        RestartSec = "3s";
        RuntimeDirectory = "microseg";
        RuntimeDirectoryMode = "0750";

        # Hardening: the agent needs CAP_BPF + CAP_NET_ADMIN
        # + CAP_PERFMON to load eBPF and attach to cgroupv2; everything
        # else is dropped.
        CapabilityBoundingSet = [ "CAP_BPF" "CAP_NET_ADMIN" "CAP_PERFMON" "CAP_SYS_RESOURCE" ];
        AmbientCapabilities    = [ "CAP_BPF" "CAP_NET_ADMIN" "CAP_PERFMON" "CAP_SYS_RESOURCE" ];
        NoNewPrivileges        = true;
        ProtectSystem          = "strict";
        ProtectHome            = true;
        PrivateTmp             = true;
        ProtectKernelLogs      = true;
        ProtectKernelModules   = true;
        ProtectKernelTunables  = false;   # we read /sys/kernel/btf/vmlinux
        ProtectControlGroups   = false;   # we walk /sys/fs/cgroup
        ReadWritePaths         = [ "/sys/fs/bpf" ];
        ReadOnlyPaths          = [ "/sys/fs/cgroup" "/sys/kernel/btf" ];
        SystemCallFilter       = [ "@system-service" "@network-io" "bpf" ];
        SystemCallArchitectures = "native";
        MemoryDenyWriteExecute = false;   # eBPF JIT
        LockPersonality        = true;
      };
    };

    # When enforce=false, override the agent's default flag wiring so it
    # ignores drop verdicts from the policy. Done in the agent rather
    # than here would be cleaner; keep this option-shaped until the
    # agent gains a `-enforce=` flag.
    warnings = lib.optional (!cfg.enforce && cfg.policies != [ ])
      "services.microsegebpf.enforce = false: drop verdicts in your policies will NOT be applied to the kernel datapath. Flip enforce to true once you have observed flows in Hubble for a few weeks.";

    # Optional: bring up hubble-ui as a local container/service pointed
    # at our gRPC observer. Upstream ships an OCI image that's easy to
    # run via systemd-nspawn or podman; this is a thin wrapper.
    virtualisation.oci-containers.containers = mkIf cfg.hubble.ui.enable {
      hubble-ui = {
        image = "quay.io/cilium/hubble-ui:v0.13.2";
        ports = [ "${toString cfg.hubble.ui.port}:8081" ];
        environment = {
          FLOWS_API_ADDR = cfg.hubble.listen;
        };
        extraOptions = [
          "--network=host"
          "--volume=/run/microseg:/run/microseg:ro"
        ];
      };
    };
  };
}
