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

    # Syslog forwarding. Same shipper unit as OpenSearch; the two
    # are independent and can be enabled together (typical SIEM
    # deployment: OpenSearch as the searchable store, syslog as
    # the SIEM ingest path with retention and alerting wired into
    # the corp's existing pipeline).
    #
    # Default mode is RFC 5425 syslog-over-TLS (port 6514). UDP
    # and unencrypted TCP are provided for compatibility with
    # legacy collectors but emit a NixOS warning when used —
    # security-relevant logs travelling cleartext is not a
    # configuration we want to make easy.
    logs.syslog = {
      enable = mkEnableOption "ship microseg-agent logs and flow events to a syslog endpoint via Vector (default: RFC 5425 syslog-over-TLS)";

      endpoint = mkOption {
        type = types.str;
        example = "syslog.corp.local:6514";
        description = ''
          host:port of the syslog collector. Port 6514 is the IANA
          assignment for RFC 5425 syslog-over-TLS; 514 is the
          legacy plain syslog port. Vector connects directly — no
          intermediate relay.
        '';
      };

      mode = mkOption {
        type = types.enum [ "tcp+tls" "tcp" "udp" ];
        default = "tcp+tls";
        description = ''
          Transport mode:

          - `tcp+tls`: RFC 5425 syslog over TLS. The only mode
            appropriate for sending policy-relevant logs across an
            untrusted network. Mandates octet-counting framing per
            the RFC.
          - `tcp`: plain TCP (RFC 6587), no encryption. Use only
            on a trusted local segment. Emits a warning at
            evaluation time.
          - `udp`: legacy BSD syslog (RFC 3164 wire framing on
            UDP). Lossy, no acknowledgements, no encryption. Use
            only when the collector cannot speak anything else.
            Emits a warning at evaluation time.
        '';
      };

      appName = mkOption {
        type = types.str;
        default = "microsegebpf";
        description = ''
          APP-NAME field of the RFC 5424 header, used by SIEMs to
          route the stream into the right ingest pipeline. Keep
          short (RFC 5424 limit is 48 ASCII chars).
        '';
      };

      facilityFlows = mkOption {
        type = types.enum [
          "kern" "user" "mail" "daemon" "auth" "syslog" "lpr"
          "news" "uucp" "cron" "authpriv" "ftp"
          "local0" "local1" "local2" "local3"
          "local4" "local5" "local6" "local7"
        ];
        default = "local4";
        description = ''
          Syslog facility for flow events (the high-volume stream).
          `local4` (numeric 20) is a common SIEM convention for
          security-relevant network logs and is the safe default.
          Switch to `auth` or `authpriv` if your SIEM routes those
          into a higher-retention or higher-priority bucket.
        '';
      };

      facilityAgent = mkOption {
        type = types.enum [
          "kern" "user" "mail" "daemon" "auth" "syslog" "lpr"
          "news" "uucp" "cron" "authpriv" "ftp"
          "local0" "local1" "local2" "local3"
          "local4" "local5" "local6" "local7"
        ];
        default = "daemon";
        description = ''
          Syslog facility for agent control-plane logs (slog
          stream on stderr). `daemon` (numeric 3) is the canonical
          choice for service control-plane chatter and matches what
          most NixOS services emit.
        '';
      };

      framing = mkOption {
        type = types.enum [ "newline_delimited" "character_delimited" "length_delimited" "bytes" ];
        default = "newline_delimited";
        description = ''
          Framing on TCP / TLS. Vector's `socket` sink supports
          `newline_delimited`, `character_delimited`,
          `length_delimited` (4-byte big-endian binary prefix —
          NOT the same as RFC 5425's ASCII-decimal octet
          counting!), and `bytes` (no framing — raw bytes).

          Default `newline_delimited` is compatible with rsyslog
          (`imtcp`), syslog-ng (`network()` driver), Splunk, and
          most cloud SIEMs. Strict RFC 5425 octet-counting requires
          `bytes` framing plus a custom VRL transform that
          prepends the ASCII length — wire that via
          `extraSettings` if your collector demands it.

          Ignored when `mode = "udp"`.
        '';
      };

      tls = {
        caFile = mkOption {
          type = types.nullOr types.path;
          default = null;
          description = ''
            CA certificate to verify the syslog server's cert
            (only used when `mode = "tcp+tls"`). Null = trust the
            system store. Must be readable by the dynamic user
            (typically /etc/ssl/certs/* with mode 0644).
          '';
        };
        certFile = mkOption {
          type = types.nullOr types.path;
          default = null;
          description = ''
            Client certificate for mTLS (only used when
            `mode = "tcp+tls"`). Pair with `keyFile`. Must be
            readable by the dynamic user.
          '';
        };
        keyFile = mkOption {
          type = types.nullOr types.path;
          default = null;
          description = ''
            Private key for mTLS (only used when `mode =
            "tcp+tls"`). Loaded via systemd's LoadCredential — the
            file may be on a path the dynamic user cannot reach
            directly (e.g. /etc/ssl/private mode 0640 root:ssl-cert),
            systemd bind-mounts it into the unit's namespace at
            startup and only the unit can read it.
          '';
        };
        keyPassFile = mkOption {
          type = types.nullOr types.path;
          default = null;
          description = ''
            Path to a file containing the passphrase for
            `keyFile`, if encrypted. Same LoadCredential
            treatment as `keyFile`.
          '';
        };
        verifyCertificate = mkOption {
          type = types.bool;
          default = true;
          description = ''
            Verify the server certificate against the CA. Set to
            false ONLY for lab debugging — disabling cert
            verification on a syslog channel that carries security
            verdicts undermines the whole point of TLS.
          '';
        };
        verifyHostname = mkOption {
          type = types.bool;
          default = true;
          description = "Verify the server hostname matches its certificate SAN.";
        };
      };

      extraSettings = mkOption {
        type = types.attrs;
        default = { };
        description = ''
          Additional Vector settings merged into the generated
          config. Use to override buffer mode, add a second sink
          fan-out (e.g. mirror to a local file), etc.
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
          # Bool flags use explicit `=true|false` form so the agent's
          # own default never silently takes over when the module
          # opts the user out — same gap that the enforce wiring used
          # to have. emit-allow is the historic offender: agent
          # default is true (verbose), module default is false (quiet).
          "-enforce=${lib.boolToString cfg.enforce}"
          "-emit-allow=${lib.boolToString cfg.emitAllowEvents}"
          "-block-quic=${lib.boolToString cfg.blockQuic}"
          "-default-egress=${cfg.defaultEgress}"
          "-default-ingress=${cfg.defaultIngress}"
          (lib.optionalString (cfg.policies != [ ]) "-policy=${policyFile}")
          "-hubble-addr=${cfg.hubble.listen}"
          "-hubble-buffer=${toString cfg.hubble.bufferSize}"
          "-resolve-every=${cfg.resolveInterval}"
          "-tls-ports=${lib.concatStringsSep "," (map toString cfg.tlsPorts)}"
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

    # Two evaluation-time warnings:
    #
    # 1. enforce=false demotes every drop verdict to log at the
    #    agent's policy-expansion stage. The flow event still
    #    fires, but the eBPF program never returns SK_DROP — fine
    #    for bake-in, dangerous if you forget to flip it.
    #
    # 2. plain TCP / UDP syslog leaks security-relevant verdicts
    #    in cleartext to the configured collector. Keep the
    #    warning loud so the operator is forced to acknowledge
    #    the trade-off.
    warnings =
      lib.optional (!cfg.enforce && cfg.policies != [ ])
        "services.microsegebpf.enforce = false: every drop verdict is demoted to log; the eBPF datapath will emit a flow event but NOT return SK_DROP. Use this for the bake-in phase only and flip enforce=true to actually contain compromised workloads."
      ++ lib.optional (cfg.logs.syslog.enable && cfg.logs.syslog.mode != "tcp+tls")
        "services.microsegebpf.logs.syslog.mode = \"${cfg.logs.syslog.mode}\": flow events and control-plane logs travel UNENCRYPTED to ${cfg.logs.syslog.endpoint}. Use \"tcp+tls\" (RFC 5425, default port 6514) unless you really need legacy compat."
      # Hubble gRPC observer has no built-in transport authentication.
      # On a Unix socket (default) the kernel mediates access via mode
      # bits + RuntimeDirectoryMode; on a TCP listener anybody who can
      # route to the host:port streams every flow event the agent
      # observes — including SNI hostnames the user reaches. Force the
      # operator to acknowledge the trade-off in the rebuild log.
      # See SECURITY-AUDIT.md §F-1.
      ++ lib.optional (!lib.hasPrefix "unix:" cfg.hubble.listen)
        "services.microsegebpf.hubble.listen = \"${cfg.hubble.listen}\": the gRPC observer has no transport authentication. A TCP listener exposes every flow event (5-tuples + SNI) to anyone who can connect. Keep the default (unix:/run/microseg/hubble.sock) unless you have a host firewall and an authenticated reverse proxy in front, or accept the operational risk explicitly."
      # hubble-ui in --network=host mode (the previous default) bound
      # the dashboard to every interface of the workstation. We've
      # since switched to a podman bridge with 127.0.0.1 host binding;
      # the warning is a defence-in-depth nudge in case an operator
      # overrides this via extraOptions.
      ++ lib.optional cfg.hubble.ui.enable
        "services.microsegebpf.hubble.ui.enable = true: the dashboard is bound to 127.0.0.1:${toString cfg.hubble.ui.port}. Forward via SSH (ssh -L) for remote access — never publish to a non-loopback interface; the UI shows the workstation's full live flow map.";

    # Optional: bring up hubble-ui as a local container/service pointed
    # at our gRPC observer. Upstream ships an OCI image that's easy to
    # run via systemd-nspawn or podman; this is a thin wrapper.
    #
    # Important: `--network=host` was the previous default — it bound
    # nginx in the container to 0.0.0.0:port on the workstation, which
    # was network-reachable and exposed the full flow map. Now we use
    # a regular podman bridge network with the host port published on
    # 127.0.0.1 only; remote access is via `ssh -L`. The volume mount
    # of /run/microseg lets the container reach the agent's Unix
    # socket without needing the host's network namespace.
    virtualisation.oci-containers.containers = mkIf cfg.hubble.ui.enable {
      hubble-ui = {
        image = "quay.io/cilium/hubble-ui:v0.13.5";
        ports = [ "127.0.0.1:${toString cfg.hubble.ui.port}:8081" ];
        environment = {
          FLOWS_API_ADDR = cfg.hubble.listen;
        };
        extraOptions = [
          "--volume=/run/microseg:/run/microseg:ro"
        ];
      };
    };

    # Optional: ship the agent's stdout (flow events) and stderr
    # (control-plane slog) from journald into one or more
    # destinations via a single Vector instance. Currently
    # supported sinks: OpenSearch (HTTP bulk) and syslog (RFC 5425
    # TLS / RFC 6587 plain TCP / RFC 3164 UDP).
    #
    # Both sinks share the same shipper unit — they read from the
    # same journald source through the same parse + filter
    # transforms. Enabling both adds two extra sinks; resource
    # cost is one Vector process either way.
    systemd.services.microsegebpf-log-shipper =
      let
        os = cfg.logs.opensearch;
        sl = cfg.logs.syslog;
        anyEnabled = os.enable || sl.enable;

        hasOSAuth = os.auth.user != null && os.auth.passwordFile != null;
        hasSlMtls = sl.tls.keyFile != null;
        hasSlKeyPass = sl.tls.keyPassFile != null;

        # RFC 5424 facility names → numeric codes (priority byte
        # is facility * 8 + severity).
        facilityCode = name: {
          kern = 0; user = 1; mail = 2; daemon = 3; auth = 4;
          syslog = 5; lpr = 6; news = 7; uucp = 8; cron = 9;
          authpriv = 10; ftp = 11;
          local0 = 16; local1 = 17; local2 = 18; local3 = 19;
          local4 = 20; local5 = 21; local6 = 22; local7 = 23;
        }.${name};

        # Credentials directory is well-known and predictable for a
        # systemd unit; build the path once for use in the JSON
        # config that Vector reads at startup.
        credDir = "/run/credentials/microsegebpf-log-shipper.service";

        # Always-on plumbing: journald source + parse + flow/agent
        # filters. The sinks themselves are spliced in conditionally.
        baseConfig = lib.recursiveUpdate {
          data_dir = "/var/lib/vector";

          sources.microseg_journal = {
            type = "journald";
            include_units = [ "microsegebpf-agent.service" ];
            current_boot_only = true;
          };

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
        } (lib.recursiveUpdate os.extraSettings sl.extraSettings);

        # ------------- OpenSearch sinks -------------
        withOpenSearch = c:
          if !os.enable then c
          else lib.recursiveUpdate c (lib.recursiveUpdate {
            sinks.opensearch_flows = {
              type = "elasticsearch";
              inputs = [ "microseg_filter_flows" ];
              endpoints = [ os.endpoint ];
              mode = "bulk";
              bulk.index = os.indexFlows;
              healthcheck.enabled = false;
            } // lib.optionalAttrs hasOSAuth {
              auth = { strategy = "basic"; user = os.auth.user; password = "\${MICROSEG_OS_PASSWORD}"; };
            } // lib.optionalAttrs (os.tls.caFile != null || !os.tls.verifyCertificate) {
              tls = { verify_certificate = os.tls.verifyCertificate; }
                // lib.optionalAttrs (os.tls.caFile != null) { ca_file = toString os.tls.caFile; };
            };
            sinks.opensearch_agent = {
              type = "elasticsearch";
              inputs = [ "microseg_filter_agent" ];
              endpoints = [ os.endpoint ];
              mode = "bulk";
              bulk.index = os.indexAgent;
              healthcheck.enabled = false;
            } // lib.optionalAttrs hasOSAuth {
              auth = { strategy = "basic"; user = os.auth.user; password = "\${MICROSEG_OS_PASSWORD}"; };
            } // lib.optionalAttrs (os.tls.caFile != null || !os.tls.verifyCertificate) {
              tls = { verify_certificate = os.tls.verifyCertificate; }
                // lib.optionalAttrs (os.tls.caFile != null) { ca_file = toString os.tls.caFile; };
            };
          } { });

        # ------------- Syslog sinks -------------
        # VRL formatter that rewrites .message in place to a valid
        # RFC 5424 line:
        #
        #   <PRI>1 TIMESTAMP HOSTNAME APP-NAME - - - JSON-BODY
        #
        # Severity is computed per event from the slog .level (agent
        # stream) or .verdict (flow stream). Facility is fixed per
        # stream and baked in at Nix evaluation time. PROCID, MSGID
        # and STRUCTURED-DATA are NIL ("-") — SIEMs that need them
        # can be added via extraSettings without changing the body.
        #
        # Imperative VRL on purpose: the equivalent expression-form
        # `sev = if ... { ... }` with nested `else if` chains
        # confuses VRL's type inference (bound variable disappears
        # at use site). Plain assignment with default is unambiguous
        # and reads the same.
        syslogFormatVRL = facility: ''
          sev = 6
          if exists(.level) {
            lvl = to_string(.level) ?? "INFO"
            if lvl == "ERROR" { sev = 3 }
            if lvl == "WARN"  { sev = 4 }
            if lvl == "INFO"  { sev = 6 }
            if lvl == "DEBUG" { sev = 7 }
          }
          if exists(.verdict) {
            v = to_string(.verdict) ?? "allow"
            if v == "drop" { sev = 4 }
            if v == "log"  { sev = 5 }
          }

          # PRI = facility * 8 + severity. Facility is bound at
          # evaluation time so the multiplication is constant-folded
          # into the integer literal below.
          pri = ${toString (facilityCode facility * 8)} + sev

          ts = format_timestamp!(now(), "%Y-%m-%dT%H:%M:%S%.6fZ")
          hn = to_string(.host) ?? "-"

          body = encode_json(.)
          .message = "<" + to_string(pri) + ">1 " + ts + " " + hn + " ${sl.appName} - - - " + body
        '';

        syslogSinkBase = inputName: {
          type = "socket";
          inputs = [ inputName ];
          mode = if sl.mode == "udp" then "udp" else "tcp";
          address = sl.endpoint;
          encoding.codec = "text";
        } // lib.optionalAttrs (sl.mode != "udp") {
          framing.method = sl.framing;
        } // lib.optionalAttrs (sl.mode == "tcp+tls") {
          tls = {
            enabled = true;
            verify_certificate = sl.tls.verifyCertificate;
            verify_hostname = sl.tls.verifyHostname;
          } // lib.optionalAttrs (sl.tls.caFile != null) {
            ca_file = toString sl.tls.caFile;
          } // lib.optionalAttrs (sl.tls.certFile != null) {
            crt_file = toString sl.tls.certFile;
          } // lib.optionalAttrs hasSlMtls {
            # Loaded via systemd LoadCredential below; the path is
            # the well-known credentials directory.
            key_file = "${credDir}/syslog_key";
          } // lib.optionalAttrs hasSlKeyPass {
            key_pass = "\${MICROSEG_SL_KEY_PASS}";
          };
        };

        withSyslog = c:
          if !sl.enable then c
          else lib.recursiveUpdate c {
            transforms.syslog_format_flows = {
              type = "remap";
              inputs = [ "microseg_filter_flows" ];
              source = syslogFormatVRL sl.facilityFlows;
            };
            transforms.syslog_format_agent = {
              type = "remap";
              inputs = [ "microseg_filter_agent" ];
              source = syslogFormatVRL sl.facilityAgent;
            };
            sinks.syslog_flows = syslogSinkBase "syslog_format_flows";
            sinks.syslog_agent = syslogSinkBase "syslog_format_agent";
          };

        finalConfig = withSyslog (withOpenSearch baseConfig);

        configFile = pkgs.writeText "microseg-vector.json"
          (builtins.toJSON finalConfig);

        # ExecStartPre: read every credential file into the matching
        # env var Vector substitutes at start time. Skipped entirely
        # if neither auth path is configured.
        prepScript = pkgs.writeShellScript "microseg-vector-prep" (
          lib.optionalString hasOSAuth ''
            MICROSEG_OS_PASSWORD="$(cat "$CREDENTIALS_DIRECTORY/os_password")"
            export MICROSEG_OS_PASSWORD
          '' +
          lib.optionalString hasSlKeyPass ''
            MICROSEG_SL_KEY_PASS="$(cat "$CREDENTIALS_DIRECTORY/syslog_key_pass")"
            export MICROSEG_SL_KEY_PASS
          ''
        );
      in
      mkIf anyEnabled {
        description =
          "Vector log shipper: microseg-agent journald → " +
          (lib.concatStringsSep " + " (
            lib.optional os.enable "OpenSearch" ++
            lib.optional sl.enable "syslog (${sl.mode})"
          ));
        wantedBy = [ "multi-user.target" ];
        after = [ "microsegebpf-agent.service" "network-online.target" ];
        wants = [ "network-online.target" ];

        serviceConfig = {
          Type = "simple";
          ExecStart = "${os.package}/bin/vector --config ${configFile}";
          Restart = "on-failure";
          RestartSec = "5s";
          DynamicUser = true;
          StateDirectory = "vector";
          StateDirectoryMode = "0700";
          SupplementaryGroups = [ "systemd-journal" ];

          # Each LoadCredential entry bind-mounts the source file
          # into $CREDENTIALS_DIRECTORY/<name>, readable by the
          # dynamic user only. The source path itself can be on a
          # restricted location (e.g. /etc/ssl/private mode 0640).
          LoadCredential =
            lib.optional hasOSAuth "os_password:${toString os.auth.passwordFile}" ++
            lib.optional hasSlMtls "syslog_key:${toString sl.tls.keyFile}" ++
            lib.optional hasSlKeyPass "syslog_key_pass:${toString sl.tls.keyPassFile}";

          ExecStartPre = lib.optional (hasOSAuth || hasSlKeyPass) prepScript;

          # General hardening — Vector only needs network egress
          # and journald read.
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
      };
  };
}
