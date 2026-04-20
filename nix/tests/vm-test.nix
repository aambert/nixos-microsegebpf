# SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
# SPDX-License-Identifier: MIT
#
# nixosTest: boot a NixOS VM with services.microsegebpf enabled, apply
# a policy that drops traffic to a fake "external" peer, then assert
# that the in-kernel datapath actually blocks the matching flow.
#
# Two-machine topology:
#
#   target  — runs services.microsegebpf with three policies:
#               (1) drop user.slice egress to peer:8080 (L3/L4)
#               (2) tls.sniDeny = ["sni-blocked.test"] (TLS peek)
#             A test user `alice` exists under /user.slice so cgroup-
#             scoped rules can be exercised.
#
#   peer    — exposes:
#               * nginx on tcp/8080 (plain HTTP, for the L3/L4 case)
#               * nginx on tcp/443  (HTTPS with a self-signed cert,
#                                    for the TLS SNI cases)
#             Listens on both IPv4 and IPv6 so SNI matching can be
#             exercised on each family — option A from the README's
#             "test IPv6 seriously" note.
#
# The test harness exits non-zero (CI fails) if any of:
#   - the agent fails to attach the cgroup_skb programs
#   - a curl that should succeed times out
#   - a curl that should be blocked succeeds
#
# Run locally with:
#   nix flake check
# or directly:
#   nix build .#checks.x86_64-linux.vm-test
{
  pkgs,
  module,
  policies,
}:
let
  # Self-signed cert for the HTTPS peer. The CN doesn't matter — curl
  # is invoked with -k, and the BPF-side SNI match runs on the SNI
  # extension in the ClientHello, not on the cert. Generated at Nix
  # eval time so the same cert is used by both the peer and any test
  # client that wants to pin it.
  selfSignedCert = pkgs.runCommand "microsegebpf-test-cert"
    {
      buildInputs = [ pkgs.openssl ];
    }
    ''
      mkdir -p $out
      openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
        -subj "/CN=microsegebpf-test" \
        -keyout $out/key.pem \
        -out    $out/cert.pem 2>/dev/null
    '';
in
pkgs.testers.runNixOSTest {
  name = "microsegebpf-vm-test";

  nodes = {

    target =
      { config, pkgs, ... }:
      {
        imports = [ module ];

        users.users.alice = {
          isNormalUser = true;
          uid = 1000;
        };

        # Add a routable IPv6 ULA address on the test VLAN so we can
        # reach the peer over IPv6 and exercise the v6 BPF path. The
        # nixosTest driver assigns IPv4 itself; for IPv6 we layer on
        # top.
        networking.interfaces.eth1.ipv6.addresses = [
          { address = "fc00::1"; prefixLength = 64; }
        ];

        # /etc/hosts entry for the FQDN drop test. The agent's policy
        # uses `host: fqdn-blocked.test`; resolution must yield the
        # peer's IPv4 deterministically (no real DNS in the test VLAN).
        networking.extraHosts = ''
          192.168.1.1  fqdn-blocked.test
        '';

        # Dedicated systemd units for the L3/L4 drop test. Using
        # `User = "alice"` with `Type = "oneshot"` gives us a stable
        # cgroup with a known unit name that the policy selector can
        # match — `su -l alice` from the test harness doesn't go
        # through pam_systemd (no controlling TTY) so it never creates
        # a /user.slice session, which broke the previous selector
        # `cgroupPath = /user.slice`.
        #
        # The 2-second sleep inside the script gives the agent's
        # inotify watcher (250 ms debounce + map sync) time to see
        # the new service cgroup and push the policy to the BPF map
        # before curl actually fires.
        systemd.services.alice-test-curl-blocked = {
          description = "Alice egress to peer:8080 — should be DROP";
          serviceConfig = { Type = "oneshot"; User = "alice"; };
          script = "${pkgs.coreutils}/bin/sleep 2 && ${pkgs.curl}/bin/curl --max-time 3 http://192.168.1.1:8080/";
        };
        systemd.services.alice-test-curl-allowed = {
          description = "Alice egress to peer:8080 from non-matching unit — should ALLOW";
          serviceConfig = { Type = "oneshot"; User = "alice"; };
          script = "${pkgs.coreutils}/bin/sleep 2 && ${pkgs.curl}/bin/curl --max-time 5 http://192.168.1.1:8080/";
        };

        # FQDN-by-host drop test. The policy below uses
        # `host: fqdn-blocked.test`; the agent will resolve it via the
        # system resolver -> /etc/hosts -> 192.168.1.1 (the peer), then
        # install a /32 entry that drops port 8080 traffic from this
        # service's cgroup.
        systemd.services.alice-test-curl-fqdn-blocked = {
          description = "Curl by FQDN to peer:8080 — should be DROP via host: rule";
          serviceConfig = { Type = "oneshot"; User = "alice"; };
          script = "${pkgs.coreutils}/bin/sleep 2 && ${pkgs.curl}/bin/curl --max-time 3 http://fqdn-blocked.test:8080/";
        };

        services.microsegebpf = {
          enable = true;
          enforce = true;
          emitAllowEvents = true;
          policies = [
            (policies.mkPolicy {
              name = "vm-test-drop-alice-blocked";
              selector = { systemdUnit = "alice-test-curl-blocked.service"; };
              egress = [
                (policies.drop {
                  cidr = "192.168.1.1/32";
                  ports = [ "8080" ];
                  protocol = "tcp";
                })
              ];
            })
            (policies.mkPolicy {
              name = "vm-test-drop-by-fqdn";
              selector = { systemdUnit = "alice-test-curl-fqdn-blocked.service"; };
              egress = [
                {
                  action = "drop";
                  host = "fqdn-blocked.test";
                  ports = [ "8080" ];
                  protocol = "tcp";
                }
              ];
            })
            (policies.mkPolicy {
              name = "vm-test-deny-sni";
              selector = { cgroupPath = "/"; };
              # Mix of exact and wildcard patterns to exercise both
              # branches of the LPM trie (NUL-terminated vs trailing
              # dot — see ARCHITECTURE.md §9.3 for the encoding).
              sniDeny = [
                "sni-blocked.test"
                "*.wildcard-blocked.test"
              ];
            })
          ];
        };

        environment.systemPackages = [ pkgs.curl ];
        networking.firewall.enable = false;
      };

    peer =
      { pkgs, ... }:
      {
        networking.firewall.enable = false;
        networking.interfaces.eth1.ipv6.addresses = [
          { address = "fc00::2"; prefixLength = 64; }
        ];

        # Two vhosts because the NixOS nginx module wires the SSL cert
        # only when `addSSL`, `forceSSL` or `onlySSL` is set; manually
        # listing `listen { ssl = true; }` skips that path and nginx
        # then refuses to start with "no ssl_certificate is defined for
        # the listen ... ssl directive".
        services.nginx = {
          enable = true;

          virtualHosts."http-test" = {
            default = true;
            listen = [
              { addr = "0.0.0.0"; port = 8080; ssl = false; }
              { addr = "[::]";    port = 8080; ssl = false; }
            ];
            locations."/" = {
              return = "200 'hello from peer (http)'";
              extraConfig = "add_header Content-Type text/plain;";
            };
          };

          virtualHosts."https-test" = {
            default = true;
            onlySSL = true;
            sslCertificate    = "${selfSignedCert}/cert.pem";
            sslCertificateKey = "${selfSignedCert}/key.pem";
            listen = [
              { addr = "0.0.0.0"; port = 443; ssl = true; }
              { addr = "[::]";    port = 443; ssl = true; }
            ];
            locations."/" = {
              return = "200 'hello from peer (https)'";
              extraConfig = "add_header Content-Type text/plain;";
            };
          };
        };
      };
  };

  testScript = ''
    start_all()

    target.wait_for_unit("microsegebpf-agent.service")
    peer.wait_for_unit("nginx.service")
    peer.wait_for_open_port(8080)
    peer.wait_for_open_port(443)

    # ----------------------------------------------------------
    # Sanity: the agent must have attached its eBPF programs and
    # pinned its maps under /sys/fs/bpf/microseg.
    # ----------------------------------------------------------
    target.succeed("test -e /sys/fs/bpf/microseg/egress_v4")
    target.succeed("test -e /sys/fs/bpf/microseg/ingress_v4")
    target.succeed("test -e /sys/fs/bpf/microseg/egress_v6")
    target.succeed("test -e /sys/fs/bpf/microseg/ingress_v6")
    target.succeed("test -e /sys/fs/bpf/microseg/tls_sni_lpm")
    target.succeed("test -e /sys/fs/bpf/microseg/tls_alpn_deny")
    target.succeed("test -S /run/microseg/hubble.sock")

    # ----------------------------------------------------------
    # L3/L4 drop selected by systemd unit name
    # ----------------------------------------------------------
    # Baseline: a curl from root (the test harness's backdoor.service)
    # is NOT subject to the alice-test-curl-blocked.service policy.
    target.succeed("curl --max-time 5 http://192.168.1.1:8080/")

    # The "allowed" alice service has no policy selector pointed at
    # it -> default verdict (allow) -> curl succeeds.
    target.succeed("systemctl start alice-test-curl-allowed.service")

    # The "blocked" alice service IS the policy target. systemd
    # `start` of a oneshot waits for completion and propagates the
    # exit code, so a non-zero curl (timeout / connect refused once
    # the BPF drop kicks in) makes systemctl exit non-zero too.
    target.fail("systemctl start alice-test-curl-blocked.service")

    # ----------------------------------------------------------
    # L3/L4 drop selected by FQDN (host: rule)
    # ----------------------------------------------------------
    # The agent resolves fqdn-blocked.test via the system resolver,
    # which hits /etc/hosts (extraHosts) and gets 192.168.1.1. That
    # IP is then installed as /32 in the egress LPM, dropping curl
    # from the matching service cgroup.
    target.fail("systemctl start alice-test-curl-fqdn-blocked.service")

    # ----------------------------------------------------------
    # TLS SNI drop — IPv4
    # ----------------------------------------------------------
    # The peer has the same cert for any hostname. We force the SNI
    # via curl --resolve so the ClientHello carries the name we want
    # to test, while the underlying TCP destination is the peer.
    #
    # Allowed SNI: handshake completes, curl exits 0 (cert is
    # self-signed, hence -k).
    target.succeed(
        "curl --max-time 5 -k --resolve sni-allowed.test:443:192.168.1.1 "
        "https://sni-allowed.test/"
    )
    # Blocked SNI: BPF drops the packet carrying the ClientHello, the
    # handshake never completes, curl errors out.
    target.fail(
        "curl --max-time 5 -k --resolve sni-blocked.test:443:192.168.1.1 "
        "https://sni-blocked.test/"
    )

    # Wildcard SNI: same blocked outcome via *.wildcard-blocked.test
    # — exercises the LPM-trie wildcard branch (entry stored with a
    # trailing dot terminator, lookup matches by prefix).
    target.fail(
        "curl --max-time 5 -k --resolve sub.wildcard-blocked.test:443:192.168.1.1 "
        "https://sub.wildcard-blocked.test/"
    )
    target.fail(
        "curl --max-time 5 -k --resolve a.b.wildcard-blocked.test:443:192.168.1.1 "
        "https://a.b.wildcard-blocked.test/"
    )
    # The bare apex of a wildcard pattern is NOT covered (`*.foo.com`
    # only matches at least one subdomain label). curl to the apex
    # must succeed.
    target.succeed(
        "curl --max-time 5 -k --resolve wildcard-blocked.test:443:192.168.1.1 "
        "https://wildcard-blocked.test/"
    )

    # ----------------------------------------------------------
    # TLS SNI drop — IPv6 (option A from README: local v6 peer)
    # ----------------------------------------------------------
    # Verify the peer is reachable on IPv6 first, otherwise the
    # `fail` below would pass for the wrong reason (no route).
    target.succeed("curl --max-time 5 -6 -g http://[fc00::2]:8080/")

    # IPv6 allowed SNI -> handshake completes.
    target.succeed(
        "curl --max-time 5 -k -6 -g "
        "--resolve sni-allowed.test:443:[fc00::2] "
        "https://sni-allowed.test/"
    )
    # IPv6 blocked SNI -> BPF v6 path must drop.
    target.fail(
        "curl --max-time 5 -k -6 -g "
        "--resolve sni-blocked.test:443:[fc00::2] "
        "https://sni-blocked.test/"
    )
  '';
}
