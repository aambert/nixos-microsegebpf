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
        When false (default), every action="drop" rule in the
        loaded policies is demoted to action="log" at the agent's
        policy-expansion stage. The eBPF datapath still emits a
        flow event for every match (visible in Hubble UI and the
        OpenSearch log shipper if enabled), but never returns
        SK_DROP — useful for a bake-in period where you want to
        watch what *would* have been dropped without actually
        breaking the workstation.

        When true, drop verdicts are enforced by the kernel
        datapath: the agent passes them through as-is and the
        cgroup_skb program returns SK_DROP on a match.

        Wired through the `-enforce=true|false` flag on the
        agent — change this option, restart the unit, and the
        next Apply tick repopulates the BPF maps with the
        translated verdicts.
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

    # Centralised log shipping. The agent itself stays focused — it
    # writes structured JSON to stdout (flow events) and stderr
    # (control-plane slog), systemd captures both into journald, and
    # a dedicated Vector instance ships them to OpenSearch. The
    # agent never speaks HTTP to OpenSearch directly.
    logs.opensearch = {
      enable = mkEnableOption "ship microseg-agent logs and flow events to OpenSearch via Vector";

      package = mkOption {
        type = types.package;
        default = pkgs.vector;
        defaultText = lib.literalExpression "pkgs.vector";
        description = "Vector derivation to use as the journald → OpenSearch shipper.";
      };

      endpoint = mkOption {
        type = types.str;
        example = "https://opensearch.corp.local:9200";
        description = "Base URL of the OpenSearch cluster (any node will do; Vector handles the bulk endpoint).";
      };

      indexFlows = mkOption {
        type = types.str;
        default = "microseg-flows-%Y.%m.%d";
        description = ''
          Strftime-templated index name for flow events (the high-
          volume stream emitted on stdout by the agent). Daily indices
          are the OpenSearch idiom for time-series — keeps shard size
          manageable and rotation cheap.
        '';
      };

      indexAgent = mkOption {
        type = types.str;
        default = "microseg-agent-%Y.%m.%d";
        description = "Strftime-templated index name for control-plane logs (the agent's slog stream on stderr).";
      };

      auth = {
        user = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "OpenSearch basic-auth user. Leave null for no auth.";
        };
        passwordFile = mkOption {
          type = types.nullOr types.path;
          default = null;
          description = ''
            Path to a file containing the OpenSearch basic-auth
            password. Read by Vector at start, never embedded in the
            unit's command line. Mode must be readable by the
            log-shipper user (root by default).
          '';
        };
      };

      tls = {
        caFile = mkOption {
          type = types.nullOr types.path;
          default = null;
          description = "CA certificate path used to verify the OpenSearch endpoint. Null = trust the system store.";
        };
        verifyCertificate = mkOption {
          type = types.bool;
          default = true;
          description = "Set to false to skip TLS certificate verification (dev-only, never in production).";
        };
      };

      extraSettings = mkOption {
        type = types.attrs;
        default = { };
        description = ''
          Additional Vector settings merged into the generated config
          (TOML-equivalent attrset). Use to add transforms, override
          the buffer mode, etc.
        '';
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
          "-enforce=${lib.boolToString cfg.enforce}"
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

    # When enforce=false the agent demotes every action="drop" rule
    # to action="log" at policy expansion time, so the kernel still
    # emits flow events but never returns SK_DROP. The warning is a
    # belt-and-suspenders reminder that bake-in mode does not
    # actually contain anything — flip enforce=true once you have
    # observed the flow surface for a few weeks.
    warnings = lib.optional (!cfg.enforce && cfg.policies != [ ])
      "services.microsegebpf.enforce = false: every drop verdict is demoted to log; the eBPF datapath will emit a flow event but NOT return SK_DROP. Use this for the bake-in phase only and flip enforce=true to actually contain compromised workloads.";

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

    # Optional: ship the agent's stdout (flow events) and stderr
    # (control-plane slog) from journald into OpenSearch via Vector.
    # See the `logs.opensearch` option block above for the user-facing
    # knobs.
    systemd.services.microsegebpf-log-shipper = mkIf cfg.logs.opensearch.enable
      (let
        os = cfg.logs.opensearch;
        hasAuth = os.auth.user != null && os.auth.passwordFile != null;

        # Build the Vector config as a Nix attrset, then serialise to
        # TOML at evaluation time. This keeps the config reviewable as
        # data (no string interpolation traps) and lets `extraSettings`
        # merge in additional sources/transforms idiomatically.
        baseConfig = lib.recursiveUpdate {
          # On-disk scratch for buffers and checkpoints. Vector
          # complains at validate time if this isn't writable, even
          # for an in-memory pipeline. Backed by systemd's
          # StateDirectory= below so DynamicUser still works.
          data_dir = "/var/lib/vector";

          # Single source: journald, restricted to the agent's unit so
          # we never accidentally ship someone else's logs.
          sources.microseg_journal = {
            type = "journald";
            include_units = [ "microsegebpf-agent.service" ];
            current_boot_only = true;
            # Pass MESSAGE through as-is; the parse_json transform
            # below decodes it.
          };

          # Parse the JSON body of every journal entry. Vector keeps
          # the original `.message` field on parse error so a non-JSON
          # line doesn't break the pipeline. `object!(parsed)` casts
          # the parsed value (typed as `any`) to an object after the
          # `is_object` guard, which makes `merge` infallible — VRL
          # rejects fallible-discarded assignments at compile time.
          transforms.microseg_parse = {
            type = "remap";
            inputs = [ "microseg_journal" ];
            source = ''
              parsed, err = parse_json(.message)
              if err == null && is_object(parsed) {
                . = merge(., object!(parsed))
              }
            '';
          };

          # Two `filter` transforms instead of a single `route`. Net
          # effect is identical — flow events go one way, control-
          # plane logs the other — but a `route` has an implicit
          # `_unmatched` output, which Vector emits a "no consumer"
          # warning for. Two filters compose more cleanly and make
          # the routing condition local to each downstream sink.
          transforms.microseg_filter_flows = {
            type = "filter";
            inputs = [ "microseg_parse" ];
            condition = ''exists(.verdict)'';
          };
          transforms.microseg_filter_agent = {
            type = "filter";
            inputs = [ "microseg_parse" ];
            condition = ''!exists(.verdict)'';
          };

          # Two sinks, one per index. Vector's "elasticsearch" sink
          # speaks the OpenSearch REST API natively (same wire format).
          sinks.opensearch_flows = {
            type = "elasticsearch";
            inputs = [ "microseg_filter_flows" ];
            endpoints = [ os.endpoint ];
            mode = "bulk";
            bulk.index = os.indexFlows;
            healthcheck.enabled = false;
          };
          sinks.opensearch_agent = {
            type = "elasticsearch";
            inputs = [ "microseg_filter_agent" ];
            endpoints = [ os.endpoint ];
            mode = "bulk";
            bulk.index = os.indexAgent;
            healthcheck.enabled = false;
          };
        } os.extraSettings;

        # Splice TLS + auth into both sinks if configured. Done after
        # the recursiveUpdate so the user can still override per-sink
        # via extraSettings if they want different auth per index.
        withAuth = c:
          if !hasAuth then c
          else lib.recursiveUpdate c {
            sinks.opensearch_flows.auth = {
              strategy = "basic";
              user = os.auth.user;
              password = "\${MICROSEG_OS_PASSWORD}";
            };
            sinks.opensearch_agent.auth = {
              strategy = "basic";
              user = os.auth.user;
              password = "\${MICROSEG_OS_PASSWORD}";
            };
          };

        withTls = c:
          if os.tls.caFile == null && os.tls.verifyCertificate then c
          else lib.recursiveUpdate c {
            sinks.opensearch_flows.tls = {
              verify_certificate = os.tls.verifyCertificate;
            } // lib.optionalAttrs (os.tls.caFile != null) {
              ca_file = toString os.tls.caFile;
            };
            sinks.opensearch_agent.tls = {
              verify_certificate = os.tls.verifyCertificate;
            } // lib.optionalAttrs (os.tls.caFile != null) {
              ca_file = toString os.tls.caFile;
            };
          };

        finalConfig = withTls (withAuth baseConfig);

        # Vector accepts TOML, YAML and JSON; we go JSON because Nix's
        # builtins.toJSON is built-in and round-trips cleanly through
        # nested attrsets.
        configFile = pkgs.writeText "microseg-vector.json"
          (builtins.toJSON finalConfig);
      in
      {
        description = "Vector log shipper: microseg-agent journald → OpenSearch";
        wantedBy = [ "multi-user.target" ];
        after = [ "microsegebpf-agent.service" "network-online.target" ];
        wants = [ "network-online.target" ];

        serviceConfig = {
          Type = "simple";
          ExecStart = "${os.package}/bin/vector --config ${configFile}";
          # Vector doesn't ship sd_notify integration in our pinned
          # release; same Type=simple rationale as the agent.
          Restart = "on-failure";
          RestartSec = "5s";
          DynamicUser = true;
          # State directory for Vector's data_dir (buffer checkpoints,
          # disk-backed buffers if ever enabled via extraSettings).
          # systemd creates /var/lib/vector under DynamicUser's
          # private namespace and bind-mounts it for the unit.
          StateDirectory = "vector";
          StateDirectoryMode = "0700";
          # Read journald (member of systemd-journal group is granted
          # by the JournalDirectory directive below).
          SupplementaryGroups = [ "systemd-journal" ];
          # Auth password file is read once at startup and stuffed into
          # the env var Vector substitutes. Nothing else is privileged.
          LoadCredential = lib.optional hasAuth
            "os_password:${toString os.auth.passwordFile}";
          ExecStartPre = lib.optional hasAuth (pkgs.writeShellScript "microseg-vector-prep" ''
            export MICROSEG_OS_PASSWORD="$(cat $CREDENTIALS_DIRECTORY/os_password)"
          '');
          # General hardening — Vector only needs network egress and
          # journald read.
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          ProtectKernelLogs = true;
          ProtectKernelModules = true;
          ProtectKernelTunables = true;
          ProtectControlGroups = true;
          RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
          SystemCallFilter = [ "@system-service" "@network-io" ];
          LockPersonality = true;
          MemoryDenyWriteExecute = false;
        };
      });
  };
}
