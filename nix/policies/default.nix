# SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
# SPDX-License-Identifier: MIT
#
# Composable policy library for nixos-microsegebpf.
#
# Two layers:
#
#   `mkPolicy` — low-level constructor. Takes a Nix attrset that
#   mirrors the YAML schema, returns a JSON string (which yaml.v3
#   parses as a single YAML document). Use this when you need a
#   one-off rule.
#
#   `baselines` — curated set of pre-built policies, expressed as
#   functions so they can be parameterised. Each baseline returns the
#   same string shape `mkPolicy` produces, so callers consume them
#   identically.
#
# Why JSON instead of hand-written YAML strings?
#   - Indentation-safe (no leading-spaces gotchas)
#   - Type-checked by Nix evaluation (typo in `egress` → eval error)
#   - Round-trips through `builtins.toJSON` deterministically, so two
#     evaluations of the same Nix produce byte-identical output
#     (good for CI cache hits and Nix store dedup)
#
# Convention for ports: always quoted strings ("443", "8000-8099").
# The agent's parser handles ranges; quoting keeps single-port and
# range entries homogeneous in the resulting JSON.
{ lib }:
let
  inherit (lib) optional;

  mkPolicy =
    {
      name,
      selector,
      egress ? [ ],
      ingress ? [ ],
      sniDeny ? [ ],
      alpnDeny ? [ ],
    }:
    builtins.toJSON {
      apiVersion = "microseg.local/v1";
      kind = "Policy";
      metadata = { inherit name; };
      spec =
        { inherit selector egress ingress; }
        // lib.optionalAttrs (sniDeny != [ ] || alpnDeny != [ ]) {
          tls = { inherit sniDeny alpnDeny; };
        };
    };

  # Convenience constructors so a baseline body reads almost like the
  # YAML it produces. Each returns a single rule attrset.
  drop =
    {
      cidr,
      ports,
      protocol ? "tcp",
    }:
    {
      action = "drop";
      inherit cidr ports protocol;
    };
  allow =
    {
      cidr,
      ports,
      protocol ? "tcp",
    }:
    {
      action = "allow";
      inherit cidr ports protocol;
    };
in
rec {
  # Re-export the low-level constructor so callers can write their own
  # one-off policies without copying the helper.
  inherit mkPolicy drop allow;

  baselines = {

    # Block direct connections to well-known public DNS resolvers
    # (Cloudflare, Google, Quad9, OpenDNS, AdGuard) on plain DNS / DoH
    # / DoT ports. Forces every name resolution through the corporate
    # resolver, defeating common DNS-tunnel and DNS-policy bypass
    # techniques. Targets every cgroup under user.slice by default.
    deny-public-dns = {
      cgroupPath ? "/user.slice",
      extraIPv4 ? [ ],
      extraIPv6 ? [ ],
    }:
    let
      v4 = [
        "1.1.1.1/32"
        "1.0.0.1/32"
        "8.8.8.8/32"
        "8.8.4.4/32"
        "9.9.9.9/32"
        "208.67.222.222/32"
        "94.140.14.14/32"
      ] ++ extraIPv4;
      v6 = [
        "2606:4700:4700::1111/128"
        "2606:4700:4700::1001/128"
        "2001:4860:4860::8888/128"
        "2001:4860:4860::8844/128"
        "2620:fe::fe/128"
      ] ++ extraIPv6;
      ports = [ "53" "443" "853" ];
    in
    mkPolicy {
      name = "baseline-deny-public-dns";
      selector = { inherit cgroupPath; };
      egress = (map (cidr: drop { inherit cidr ports; protocol = "tcp"; }) v4)
            ++ (map (cidr: drop { inherit cidr ports; protocol = "tcp"; }) v6)
            ++ (map (cidr: drop { inherit cidr ports; protocol = "udp"; }) v4);
    };

    # Restrict sshd ingress to a single CIDR. Useful for jump-host
    # patterns where the workstation should accept SSH only from the
    # corporate bastion.
    sshd-restrict = {
      allowFrom,
      port ? "22",
    }:
    mkPolicy {
      name = "baseline-sshd-restrict";
      selector = { systemdUnit = "sshd.service"; };
      ingress = [ (allow { cidr = allowFrom; ports = [ port ]; }) ];
    };

    # Deny outbound to RFC1918 from the user session. Pentest-style
    # hardening: prevents a compromised browser/mail client from
    # scanning or pivoting to internal-network targets.
    deny-rfc1918-from-user-session = {
      cgroupPath ? "/user.slice",
      ports ? [ "22" "80" "443" "445" "3389" "8080" ],
    }:
    mkPolicy {
      name = "baseline-deny-rfc1918-from-user-session";
      selector = { inherit cgroupPath; };
      egress = [
        (drop { cidr = "10.0.0.0/8";    inherit ports; })
        (drop { cidr = "172.16.0.0/12"; inherit ports; })
        (drop { cidr = "192.168.0.0/16"; inherit ports; })
      ];
    };

    # Deny SMTP egress except to a single relay. Pairs with corporate
    # MTA setups where outbound mail must go through the relay.
    smtp-relay-only = {
      relayCIDR,
      port ? "25",
    }:
    mkPolicy {
      name = "baseline-smtp-relay-only";
      selector = { cgroupPath = "/"; };
      egress = [
        (allow { cidr = relayCIDR; ports = [ port ]; })
        (drop  { cidr = "0.0.0.0/0"; ports = [ port ]; })
      ];
    };

    # Block egress to a list of known C2 / malware sinkhole IPs. Caller
    # supplies the list (typically generated from a threat-intel feed
    # at deploy time).
    deny-threat-feed = {
      ips,
      cgroupPath ? "/",
      ports ? [ "80" "443" "8080" "8443" ],
    }:
    mkPolicy {
      name = "baseline-deny-threat-feed";
      selector = { inherit cgroupPath; };
      egress = map (cidr: drop { inherit cidr ports; }) ips;
    };

    # TLS SNI deny list. Drops TLS connections whose ClientHello SNI
    # matches the supplied hostnames — the in-kernel parser inspects
    # the cleartext SNI and returns SK_DROP without ever decrypting.
    # The TLS maps are global (keyed only on the FNV-64 hash of the
    # hostname), so the selector here is documentary; the deny applies
    # to every cgroup. Useful to block CDN-hosted destinations that
    # share an IP with legitimate sites (so an IP-based rule would
    # over-block).
    #
    # Caveat: TLS 1.3 ECH (Encrypted Client Hello) is being deployed
    # — once a destination negotiates ECH, the SNI is encrypted and
    # this match silently fails open. Plan for a 2-3 year horizon.
    deny-sni =
      { hostnames }:
      mkPolicy {
        name = "baseline-deny-sni";
        selector = { cgroupPath = "/"; };
        sniDeny = hostnames;
      };

    # FQDN-resolved L3/L4 deny list. Drops egress to every IP the
    # given hostnames currently resolve to (on the supplied ports +
    # protocol). The agent re-resolves on every Apply, so the rule
    # follows the destination as its DNS records rotate — useful for
    # CDN-fronted services where the IPs change frequently and a
    # static CIDR list goes stale.
    #
    # Caveat: this matches whatever the *agent's* resolver returns,
    # not what the application itself resolved. For load-balanced
    # destinations with many IPs, the two views can briefly diverge;
    # the next Apply round catches up.
    deny-host =
      { hostnames,
        ports ? [ "443" ],
        protocol ? "tcp",
        cgroupPath ? "/",
      }:
      mkPolicy {
        name = "baseline-deny-host";
        selector = { inherit cgroupPath; };
        egress = map (h: {
          action = "drop";
          host   = h;
          inherit ports protocol;
        }) hostnames;
      };

    # ALPN deny list. Drops TLS connections that advertise any of the
    # supplied ALPN identifiers. Niche but powerful: in air-gapped
    # deployments where only specific protocols are allowed, listing
    # everything except the legitimate ones blocks novel beacons that
    # use a custom ALPN.
    #
    # Common ALPN strings: "h2" (HTTP/2), "http/1.1", "h3" (HTTP/3),
    # "imap", "smtp", "ftp", "stun.turn".
    deny-alpn =
      { protocols }:
      mkPolicy {
        name = "baseline-deny-alpn";
        selector = { cgroupPath = "/"; };
        alpnDeny = protocols;
      };

  };
}
