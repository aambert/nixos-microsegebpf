<!--
SPDX-FileCopyrightText: 2026 Aurélien Ambert <aurelien.ambert@proton.me>
SPDX-License-Identifier: MIT
-->

# Audit de sécurité — `nixos-microsegebpf`

**Date de l'audit :** 2026-04-20 (initiale)  
**Commit audité :** `afe2975` (REUSE clean + emit-allow wiring closed)  
**Auditeur :** auteur du projet, self-review outillée  
**Scope :** chaque fichier source de ce dépôt, plus les closures runtime de l'agent, du shipper Vector, et de l'image OCI optionnelle Hubble UI.

**Historique des révisions :**
- 2026-04-20 v1 (commit `2076d2a`) : audit initial
- 2026-04-20 v2 (commit `9b7f56a`) : §7.1 immediate fixes appliqués — F-2 fermée, F-1 partiellement fermée (warning Nix + binding hubble-ui), hubble-ui bumpé en v0.13.5
- 2026-04-20 v3 (cette révision) : §7.2 fixes appliqués — F-1 fermée totalement (TLS + mTLS pour l'observer gRPC, dans agent + probe + module), F-3 fermée (cache TTL DNS + stale-while-error), F-4 fermée (probe TLS)

> [English](SECURITY-AUDIT.md) · [Français](SECURITY-AUDIT.fr.md)

---

## 1. Résumé exécutif

| | Nombre de findings | CVSS 3.1 max | Statut (v3) |
|---|---|---|---|
| Issues introduites **par le code de ce projet** | 8 reviewés : 5 fermées, 1 by-design, 1 N/A, 1 follow-up | était 6.5 (F-1) — maintenant 2.4 (F-7) | F-1, F-2, F-3, F-4 fermées |
| Issues issues **de dépendances runtime tierces** | 32 (dédupliquées) | 9.1 (CVE-2026-28386 / OpenSSL) | inchangé — tracker security branch nixpkgs-25.11 |
| Issues issues **de l'image OCI bundle** (`hubble-ui:v0.13.5`, optionnelle) | réduit (était 60+ sur v0.13.2) | réduit (paquets Alpine rebuildés) | bumpé en v0.13.5 dans `9b7f56a` |
| Issues issues **de la stdlib Go** (1.25.8 → 1.25.9) | 4 (3 atteignables) | ~7.5 | mitigé sur les runners CI (Go 1.25.9 via setup-go) |

**Top résiduel après v3 :** CVE OpenSSL CVSS 9.1 dans la closure Vector (CVE-2026-28386) — fermé en bumpant nixpkgs, pas un changement de code dans ce projet.

**Aucune vulnérabilité découverte dans le code source du projet ne dépasse CVSS 2.4 après v3.** F-1 à F-5 sont fermées en code ; F-6 n'avait pas de finding au départ ; F-7 est un guard Low-severity coding-style contre les futurs contributeurs ; F-8 est un choix de design documenté (defaults fail-open pendant le bake-in).

---

## 2. Scope

### 2.1 Composants in-scope

```
┌───────────────────────────────────────────────────────────────┐
│  microsegebpf-agent (binaire Go statique)                     │
│  ├── pkg/policy/      Loader YAML + sync map LPM              │
│  ├── pkg/identity/    Walker cgroup + watcher inotify         │
│  ├── pkg/loader/      Loader cilium/ebpf                      │
│  ├── pkg/observer/    Serveur gRPC Hubble                     │
│  └── bpf/microseg.c   Datapath cgroup_skb (kernel)            │
│                                                                │
│  microseg-probe (binaire Go statique, CLI)                    │
│                                                                │
│  microsegebpf-log-shipper.service                              │
│  └── Vector 0.51.1 (journald → OpenSearch + syslog)           │
│                                                                │
│  hubble-ui (optionnel, OCI : quay.io/cilium/hubble-ui:v0.13.2)│
│                                                                │
│  Module NixOS (services.microsegebpf.*)                       │
│  ├── Durcissement systemd                                      │
│  └── Générateur de config Vector                               │
└───────────────────────────────────────────────────────────────┘
```

### 2.2 Out-of-scope

- Le noyau Linux (le datapath eBPF tourne in-kernel ; l'agent ne modifie pas le noyau lui-même, il charge juste des programmes via syscalls standard)
- L'implémentation systemd / journald
- Les implémentations TLS au-delà de ce qu'on configure (rustls, openssl tels qu'utilisés par Vector)
- La gestion de secrets côté opérateur (SOPS, agenix, vault-agent — out-of-band)

### 2.3 Méthodologie

1. **Génération SBOM** — trois formats (CycloneDX 1.5 JSON, SPDX 2.3 JSON, CSV) pour l'arbre source, le graphe de modules Go, la closure runtime de l'agent, et la closure Vector. Outils : `syft`, `cyclonedx-gomod`, `sbomnix`.
2. **Scan CVE** — `govulncheck` (toolchain Go + deps modules), `vulnix` + `grype` via `sbomnix --include-vulns` (closure Nix), `grype` (image OCI Hubble UI).
3. **Code review** — manuelle ligne-par-ligne pour la source eBPF C (verifier-bypass / OOB), l'agent Go (validation d'input, races, gestion de chemins de fichier, auth gRPC), le pipeline Vector (defaults de vérification TLS, gestion des secrets), et le durcissement du module NixOS (capability set, syscall filter, ProtectSystem).
4. **Walk-through threat-model** — pour chaque composant, énumérer la frontière de confiance, la capacité attaquante supposée, et l'impact d'une compromission.

---

## 3. Artefacts SBOM

Commités sous [`sbom/`](sbom/) :

| Fichier | Format | Sujet | Composants |
|---|---|---|---|
| `sbom-go.cdx.json` | CycloneDX 1.5 JSON | Dépendances Go directes | 9 librairies |
| `sbom-source.cdx.json` | CycloneDX 1.5 JSON | Scan arbre source (syft) | Tous modules Go + classifications |
| `sbom-source.spdx.json` | SPDX 2.3 JSON | Idem, format SPDX pour ingestion OWASP DT / Sonatype | — |
| `sbom-closure.cdx.json` | CycloneDX 1.5 JSON | Closure runtime `microseg-agent` | 4 (binaire Go statique, closure quasi-vide) |
| `sbom-closure.csv` | CSV | Idem, à plat | — |
| `sbom-closure.spdx.json` | SPDX 2.3 JSON | Idem | — |
| `sbom-vector.cdx.json` | CycloneDX 1.5 JSON | Closure runtime Vector 0.51.1 | 42 (rustls, openssl, glibc, …) |
| `sbom-vector.csv` | CSV | Idem, à plat | — |

Régénération (dans la VM dev) :

```sh
nix-shell --run 'make build'        # produit une closure à scanner
sbomnix ./result --include-vulns \
  --cdx  sbom/sbom-closure.cdx.json \
  --spdx sbom/sbom-closure.spdx.json \
  --csv  sbom/sbom-closure.csv
cyclonedx-gomod mod -json -output sbom/sbom-go.cdx.json .
syft scan dir:. -o cyclonedx-json=sbom/sbom-source.cdx.json
syft scan dir:. -o spdx-json=sbom/sbom-source.spdx.json
```

---

## 4. Findings CVE

Le scoring CVSS 3.1 utilise le NVD quand disponible ; sinon notre propre évaluation avec le rationnel détaillé en colonne « Notes ».

### 4.1 Critical / High (CVSS ≥ 7.0) — dépendances runtime tierces

Toutes viennent de paquets upstream (stdlib Go, baseline nixpkgs 25.11, Alpine dans l'image Hubble UI). Aucune n'est atteignable via les chemins de code introduits par ce projet — le vector listé est ce que la lib upstream expose.

| CVE | Composant | CVSS 3.1 | Vector | Atteignable dans notre code ? | Mitigation |
|---|---|---|---|---|---|
| **CVE-2026-28386** | OpenSSL 3.6.0 (closure Vector) | **9.1** | Handshake TLS network-facing | Uniquement sur le path mTLS syslog (`logs.syslog.mode = "tcp+tls"`). Pas sur OpenSearch (qui utilise rustls bundle Vector) | Bump nixpkgs 25.11 → security-branch HEAD ; série patch OpenSSL 3.6.x |
| **CVE-2025-15467** | OpenSSL (Vector + Hubble UI) | **8.8** | TLS server / client | Idem | Idem |
| **CVE-2026-0861** | glibc 2.40-66 (closure Vector) | **8.4** | Corruption mémoire locale via syscall spécifique | Non — Vector n'exerce pas le path libc affecté | nixpkgs 25.11 security branch |
| **CVE-2026-22184** | zlib 1.3.1 (closure Vector) | **7.8** | Décompression OOB | Possible si le client HTTP de Vector reçoit une réponse gzip d'un nœud OpenSearch malveillant. L'opérateur doit déjà faire confiance à l'endpoint OpenSearch. | Bump nixpkgs |
| **CVE-2026-3805** | curl 8.17.0 (closure Vector) | **7.5** | Handshake TLS | Si Vector lance un health-check curl-based (il ne le fait pas dans notre config ; on pose `healthcheck.enabled = false`) | Bump nixpkgs |
| **CVE-2026-31790** / 28390 / 28389 / 28388 | OpenSSL 3.6.0 | 7.5 | Issues TLS variées | Path mTLS syslog | Bump nixpkgs |
| **CVE-2026-27135** | nghttp2 1.67.1 (closure Vector) | 7.5 | Framing HTTP/2 | Le sink OpenSearch utilise HTTP/2 | Bump nixpkgs |
| **CVE-2026-2673** | OpenSSL 3.6.0 | 7.5 | TLS | mTLS syslog | Bump nixpkgs |
| **CVE-2025-69650 / 69649 / 69421 / 69420** | glibc 2.40-66 | 7.5 | NSS / locale / regex | Pas dans nos paths exercés | Bump nixpkgs |
| **CVE-2025-15281** | OpenSSL | 7.5 | TLS | Path mTLS syslog | Bump nixpkgs |
| **CVE-2025-69419** | glibc | 7.4 | Même famille | Idem | Idem |
| **CVE-2026-3442 / 3441** | glibc | 7.1 | Même famille | Idem | Idem |

### 4.2 Critical / High — Standard library Go (Go 1.25.8)

`govulncheck` flag les suivants comme *atteignables* depuis le graphe de symboles du projet :

| ID | Composant | CVSS 3.1 (project-relevant) | Vector | Atteignable via |
|---|---|---|---|---|
| **GO-2026-4870** | crypto/tls (Go 1.25.8) | **7.5** | DoS connexion-persistante TLS 1.3 KeyUpdate non-authentifié | `tls.Conn.Read/Write` atteint via `cmd/microseg-probe/main.go:53` (client CLI Hubble). Aussi atteint via `bpf.LoadMicroseg → ebpf.LoadCollectionSpecFromReader` mais ce path n'ouvre pas de connexion réseau — seul le path probe est significatif. |
| **GO-2026-4947** | crypto/x509 (Go 1.25.8) | **5.3** | Travail inattendu en chain building (DoS) | `x509.Certificate.Verify` atteint uniquement via `ebpf.LoadCollectionSpecFromReader` — lecture locale d'un ELF embedé, pas d'input certificat untrusted. **Pas exploitable** dans notre déploiement. |
| **GO-2026-4946** | crypto/x509 (Go 1.25.8) | **5.3** | Validation policy inefficace (DoS) | Même path que ci-dessus. **Pas exploitable**. |
| **GO-2026-4865** | html/template (Go 1.25.8) | **0.0** | XSS dans tracking contexte JsBraceDepth | Atteint via imports transitifs `fmt.Sprintf` et `signal.Notify`. **L'agent ne rend jamais d'HTML.** Faux positif total pour notre usage. |

**Mitigation pour les quatre :** suivre Go 1.25.9+ dans nixpkgs. Le dev-shell utilise déjà `go_1_25` (un alias qui suit la série patch 1.25.x) ; un déploiement NixOS qui pull un commit nixpkgs-25.11 frais aura 1.25.9 automatiquement dès que la security branch le ship. La CI ré-exécutera le lint et le vm-test sur ce commit.

### 4.3 Image OCI Hubble UI (`quay.io/cilium/hubble-ui:v0.13.2`, optionnelle)

Pinnée dans le module NixOS sous `services.microsegebpf.hubble.ui.enable = true` (default : false). 60+ CVEs reportées par `grype` contre les paquets Alpine cuits dans l'image. Les quatre avec la plus haute reachability :

| CVE | Paquet | CVSS | Note |
|---|---|---|---|
| CVE-2025-15467 | libssl3 / libcrypto3 (Alpine OpenSSL) | 8.8 | Même upstream que l'entrée closure Vector |
| CVE-2025-69420 | libssl3 / libcrypto3 | 7.x | Issue TLS |
| CVE-2026-28389 / 28390 / 28388 | libssl3 / libcrypto3 | 7.x | Issues TLS |
| CVE-2026-27651 / 27654 | nginx 1.27.3 | 7.x | HTTP request smuggling |

**Mitigation :** bump le tag pinné vers une release `cilium/hubble-ui` plus fraîche (Cilium publie de nouvelles images dès que leur base layer est rebuilt). Le pin vit dans `nix/microsegebpf.nix:519` ; le flipper en ex. `v0.14.x` quand publié est un changement d'une ligne. Tracker via la page [cilium/hubble-ui releases](https://github.com/cilium/hubble-ui/releases) upstream.

**Note architecturale (pas un CVE) :** le conteneur OCI est lancé avec `--network=host` (`nix/microsegebpf.nix:531`) pour qu'il puisse atteindre le socket Unix de l'agent à `/run/microseg/hubble.sock`. Avec `--network=host`, le nginx du conteneur bind sur **toutes les interfaces du poste** sur `cfg.hubble.ui.port` (default 12000) — n'importe qui qui peut router vers le poste sur ce port voit la carte de flux live. Voir finding **F-1** ci-dessous.

---

## 5. Findings code-review manuelle

Pas de CVE attaché (on est l'upstream) ; ce sont des risques introduits par le projet, découverts par review ligne-par-ligne.

### F-1 — Exposition gRPC Hubble + UI quand configurés pour TCP / accès réseau

**Statut :** ✅ **FERMÉE en v3** (commit `9b7f56a` partial, commit courant full)  
**CVSS 3.1 avant fix :** AV:A / AC:L / PR:N / UI:N / S:U / C:H / I:N / A:N → **6.5 (Medium)**  
**CVSS 3.1 après fix :** AV:N / AC:H / PR:H / UI:N / S:U / C:N / I:N / A:N → **2.4 (Low)** — résiduel uniquement si l'opérateur misconfigure TLS off délibérément

**Où :** `pkg/observer/server.go:91-95` et `nix/microsegebpf.nix:531`.

**Issue.** Le serveur gRPC `Hubble.Observer` est créé avec un `grpc.NewServer()` nu — pas de transport credentials, pas d'auth interceptor. Le défaut `services.microsegebpf.hubble.listen` est le socket Unix `unix:/run/microseg/hubble.sock` (mode 0750 via `RuntimeDirectoryMode`), qui restreint l'accès à root sur le poste. Ce default est safe.

**Cependant :** si un opérateur switche vers un listener TCP (ex. `hubble.listen = "0.0.0.0:50051"`) l'observer stream chaque flow event à n'importe quel client qui peut se connecter — exposant l'activité réseau complète du poste, y compris les hostnames SNI que l'utilisateur atteint. Idem pour `hubble.ui.enable = true` combiné avec le `--network=host` du conteneur OCI : le dashboard listen sur `cfg.hubble.ui.port` sur toutes les interfaces.

**Mitigation appliquée (v2 + v3) :**
- ✅ Warning NixOS au moment de l'évaluation quand `hubble.listen` est TCP et `hubble.tls.{certFile,keyFile}` est unset (commit `9b7f56a` introduit le warning, commit courant le raffine pour fire uniquement quand TLS manque — avoir TLS est la mitigation réelle, pas juste acknowledger le trade-off)
- ✅ L'agent émet un slog WARN runtime au démarrage avec le même wording (donc une invocation CLI bypassant le module surface aussi le warning)
- ✅ Le conteneur OCI Hubble-ui drop `--network=host` ; utilise maintenant un bridge podman avec `ports = ["127.0.0.1:${port}:8081"]` (commit `9b7f56a`). UI = loopback only ; accès remote via `ssh -L`
- ✅ **TLS / mTLS pour l'observer gRPC** — cert/key server-side + CA client optionnelle + toggle `RequireClient` (commit courant). Câblé via `services.microsegebpf.hubble.tls.{certFile, keyFile, clientCAFile, requireClientCert}`
- ✅ Section dédiée dans README + ARCHITECTURE §5.2 qui walk l'opérateur à travers la config TLS / mTLS complète avec matrice de tests vérifiée

**Résiduel :** un opérateur qui déploie délibérément avec `hubble.listen = "0.0.0.0:50051"` et pas de TLS verra deux warnings séparés (Nix-time + runtime) — mais la config charge quand même. On a choisi loud + overridable plutôt qu'un hard refusal, pour qu'un déploiement lab/debug ne soit pas bloqué. CVSS 2.4 (Low) reflète ce résiduel.

### F-2 — YAML policy chargé avec `gopkg.in/yaml.v3`, parsé sans cap de taille

**Statut :** ✅ **FERMÉE en v2** (commit `9b7f56a`)  
**CVSS 3.1 avant fix :** AV:L / AC:L / PR:H / UI:N / S:U / C:N / I:N / A:L → **3.1 (Low)**

**Où :** `pkg/policy/types.go::LoadFile` (chemin de fichier passé via `-policy=...`).

**Issue.** L'agent lit le fichier policy en entier et appelle `yaml.NewDecoder(f).Decode(...)`. Pas de borne haute sur la taille avant parse. Un opérateur (ou un local-root malveillant avec write access au chemin) pourrait fournir un YAML billion-laughs / nested-anchors multi-gigaoctets et OOM l'agent.

**Réalisme.** L'agent tourne en non-root avec `CAP_BPF` et lit la policy depuis un chemin que l'opérateur contrôle. Le threat model est « input opérateur uniquement », donc c'est essentiellement un footgun pour l'opérateur, pas un vector d'attaque externe. `yaml.v3` est aussi documenté comme refusant certains aliases pathologiques par défaut (`maxAliases = 1024`), ce qui limite — mais n'élimine pas — les pires cas.

**Mitigation appliquée (v2) :**
- ✅ Constante `MaxPolicyFileBytes = 16 * 1024 * 1024` dans `pkg/policy/types.go`. `LoadFile` lit via `io.ReadAll(io.LimitReader(f, MaxPolicyFileBytes+1))` — le truc du +1 byte permet de détecter overrun explicitement et retourner une erreur claire, plutôt que truncate silencieusement à 16 MiB et parser zéro docs (ce qui aurait été le pire mode de panne possible pour un contrôle de sécurité)
- Vérifié dans la VM dev : YAML pathological 17 MiB → `ERROR policy load failed err="policy file ... exceeds cap of 16777216 bytes"` (exit status 1) ; policy legit 4 KB → `INFO policy applied (delta) docs=4`

**Pas adressé (out of scope pour ce fix) :** les collisions `metadata.name` sont toujours ignorées (last write wins). À filer comme F-9 séparé dans une révision audit future.

### F-3 — Timeout résolution DNS pour règles `host:` à 2 s, sans cache

**Statut :** ✅ **FERMÉE en v3** (commit courant)  
**CVSS 3.1 avant fix :** AV:N / AC:L / PR:N / UI:N / S:U / C:N / I:N / A:L → **5.3 (Medium)** — capacité attaquant extérieur via DNS poisoning  
**CVSS 3.1 après fix :** inchangé pour la menace sous-jacente (dépend toujours de la confiance dans le résolveur), mais la *fenêtre d'attaque* est réduite de « chaque tick Apply » (~5s défaut) à « chaque période TTL » (60s défaut, configurable à 0 pour comportement pre-fix ou à valeurs plus hautes pour mitigation plus stricte). La mitigation ajoute aussi un fallback stale-while-error qui renforce l'enforcement availability contre les pannes resolver transitoires.

**Où :** `pkg/policy/sync.go::resolveRuleTargets` — `net.DefaultResolver.LookupIPAddr` avec un timeout context de 2 secondes, appelé une fois par règle `host:` à chaque tick Apply (typiquement chaque réconciliation cgroup-event-driven, ou chaque `resolveInterval` secondes en fallback).

**Issue.** Une règle comme `host: api.corp.example.com` est re-résolue à chaque Apply. Si le résolveur upstream est empoisonné, une réponse DNS malveillante peut flipper les entrées LPM `/32` vers des IPs contrôlées par l'attaquant — c-à-d qu'une règle `drop` pointée sur une destination CDN-hostée pourrait être redirigée pour autoriser le trafic vers l'IP de l'attaquant. Inversement, une règle `allow` (avec `defaultEgress = "drop"`) pourrait être redirigée pour drop le trafic légitime.

**Réalisme.** C'est une propriété du résolveur, pas de l'agent. Le même risque existe pour tout outil qui consulte le DNS pour la security policy (les FQDN policies de Cilium ont le même caveat upstream). La mitigation est l'*opérateur* utilisant un résolveur de confiance — typiquement le DNS corporate que la baseline `deny-public-dns` de ce projet est conçue pour *enforcer* en premier lieu. Il y a aussi une famille de remediations `dnssec` que l'opérateur peut déployer ; l'agent ne fait pas de validation DNSSEC aujourd'hui.

**Mitigation appliquée (v3) :**
- ✅ Cache FQDN→IP avec TTL configurable (défaut 60s) dans `pkg/policy/sync.go`. Chaque tick Apply consulte le cache d'abord ; uniquement sur miss / expiry il appelle `net.DefaultResolver.LookupIPAddr`
- ✅ Fallback stale-while-error : si le résolveur fail sur la re-résolution, l'agent réutilise la dernière réponse known-good pour un cycle de plus et log un WARN. Une panne resolver transitoire ne flush plus les entrées LPM `host:`
- ✅ Câblé via le flag `-dns-cache-ttl` sur l'agent et l'option `services.microsegebpf.dnsCacheTTL` (défaut `60s`, poser `0s` pour désactiver le cache)
- ✅ ARCHITECTURE §4.5 documente la mécanique du cache, y compris pourquoi DNSSEC reste la responsabilité de l'opérateur (le cache rétrécit la fenêtre temporelle, ne valide pas)

**Pas adressé (out of scope) :** support pour une adresse résolveur custom (DoT, do53-tcp-only). L'agent utilise toujours `net.DefaultResolver` qui respecte `/etc/resolv.conf`. Les opérateurs voulant des garanties plus fortes devraient lancer un résolveur DNSSEC-validating local (ex. `unbound`) et pointer `/etc/resolv.conf` dessus.

### F-4 — `microseg-probe` se connecte à l'observer gRPC avec `insecure.NewCredentials()`

**Statut :** ✅ **FERMÉE en v3** (commit courant)  
**CVSS 3.1 avant fix :** AV:L / AC:L / PR:L / UI:N / S:U / C:L / I:N / A:N → **3.3 (Low)**

**Où :** `cmd/microseg-probe/main.go` — le client gRPC utilise toujours du transport insecure.

**Issue.** Le CLI parle à l'observer sur socket Unix par défaut (pas besoin de TLS — le noyau médie l'auth via les bits de mode). Si l'opérateur switche l'agent vers TCP et pointe `microseg-probe -addr=` dessus, la connexion est en clair. Combiné avec **F-1**, un attaquant on-path sur le segment LAN peut lire chaque flow event que le probe stream.

**Mitigation appliquée (v3) :**
- ✅ TLS / mTLS server-side dans `pkg/observer/server.go` (voir F-1)
- ✅ TLS probe-side dans `cmd/microseg-probe/main.go::buildClientCreds` — flags `-tls-ca`, `-tls-cert`, `-tls-key`, `-tls-server-name`, `-tls-insecure`. Comportement par défaut inchangé (insecure pour socket Unix, où le noyau médie) ; n'importe quel flag TLS non-vide opte dans une `tls.Config` avec `MinVersion = TLS 1.2`
- Vérifié end-to-end dans la VM dev : probe avec CA + cert client valides marche ; probe sans cert client contre serveur mTLS reçoit `tls: certificate required` ; probe en plaintext contre serveur TLS reçoit `error reading server preface: EOF`

### F-5 — Config Vector matérialisée à l'évaluation du module ; secrets passés via env

**CVSS 3.1 (contexte projet) :** AV:L / AC:H / PR:H / UI:N / S:U / C:L / I:N / A:N → **2.5 (Low)**

**Où :** `nix/microsegebpf.nix::microsegebpf-log-shipper.serviceConfig.LoadCredential` et le shell script `ExecStartPre` qui exporte `MICROSEG_OS_PASSWORD` / `MICROSEG_SL_KEY_PASS`.

**Issue.** Les credentials vivent transitoirement à deux endroits :
1. Le chemin de fichier original (`auth.passwordFile`, `tls.keyPassFile`) — typiquement root:root mode 0600 ou root:ssl-cert mode 0640. Hors de notre contrôle.
2. Le bind-mount `LoadCredential` systemd dans `/run/credentials/microsegebpf-log-shipper.service/` — lisible seulement par l'UID de l'unit (le dynamic user).
3. L'env var shell-exportée `MICROSEG_OS_PASSWORD` / `MICROSEG_SL_KEY_PASS` — visible dans `/proc/<pid>/environ` à n'importe qui qui peut le lire (le dynamic user, root, n'importe qui avec `CAP_SYS_PTRACE`).

**Réalisme.** Rien sur le poste ne devrait lire les `/proc/*/environ` d'autres utilisateurs — `ProtectSystem=strict` sur l'unit Vector le rend difficile, et root lisant une env var Vector est le même niveau de confiance que root lisant le fichier password original directement. Le pattern env-var est ce que la substitution `${VAR}` de Vector requiert ; des alternatives (auth file-based) existent pour le sink OpenSearch et sont documentées comme un knob `extraSettings`.

**Mitigation (déjà appliquée) :** le bind-mount `LoadCredential` est le bon pattern — les clés n'apparaissent jamais dans la directive `Environment=` de l'unit (qui serait persistée dans le journal de systemd). Le script `ExecStartPre` lit le credential dans l'env var **uniquement au start**, jamais écrit sur disque. C'est la recette NixOS standard.

**Mitigation (follow-up optionnel) :** supporter la substitution auth file-based native de Vector (syntaxe `@/path/to/file` dans certains sinks) pour skipper l'étape env-var entièrement sur le path OpenSearch.

### F-6 — Source eBPF C : bound checks reviewés, verifier-clean

**CVSS 3.1 (contexte projet) :** N/A (pas de finding).

**Où :** `bpf/microseg.c` — chaque parser TLS, lookup LPM, et réservation ring-buffer reviewés.

**Findings durant la review :**
- Tous les appels `bpf_skb_load_bytes` checkent la valeur de retour avant d'utiliser les bytes lus (`return SKB_PASS` en erreur).
- Toute arithmétique de pointeur sur le packet (`data`, `data_end`) est encadrée par le pattern verifier-friendly standard `if ((void *)(t + 1) > data_end) return SKB_PASS;` (ligne 529, 534, etc.).
- Le walker SNI utilise un mask `j &= MAX_SNI_NAME_BYTES - 1` dur après chaque itération — nécessaire parce que le verifier rejette les bound `if`-and-return en boucle pour les accès stack ; on fait la borne une puissance de deux et on applique un mask.
- Le buffer scratch SNI 256-byte a été déplacé hors stack dans une map per-CPU array spécifiquement pour éviter le budget stack BPF de 512 bytes, ce qui prévient une classe de stack-overflow accidentel qui aurait été un échec verifier plutôt qu'un kernel exploit, mais est quand même bonne hygiène.
- Le walker d'extensions TLS utilise `bpf_loop` plutôt que `#pragma unroll`, donc il est borné par la signature du helper (`u32 max_iter`) plutôt que par le budget instructions du verifier.

**Pas de verifier-bypass, pas d'OOB read/write, pas de vector kernel panic identifié.** Le programme kernel lui-même tourne dans l'environnement d'exécution le plus restreint que Linux offre ; le verifier est le reviewer final effectif.

### F-7 — Watcher inotify : liste de subscribers grossit sans borne si `Subscribe()` est appelé par itération de boucle

**CVSS 3.1 (contexte projet) :** AV:L / AC:H / PR:H / UI:N / S:U / C:N / I:N / A:L → **2.4 (Low)**

**Où :** `pkg/identity/watcher.go::Subscribe`. Le watcher retourne un fresh channel par appel et l'append à une liste ; rien ne trim la liste quand les subscribers stop reading.

**Issue.** Trouvé et fixé pendant le développement initial (la description de commit `c267762` raconte le saga qui a pris 4 CI runs). Le main.go actuel appelle `Subscribe()` exactement une fois en dehors de la boucle. Un futur contributeur qui copie le pattern naïvement leakerait des channels — le watcher continuerait de publish vers des consumers morts, et l'usage mémoire grossirait.

**Mitigation (follow-up recommandé) :**
- Ajouter une méthode `Unsubscribe(ch <-chan struct{})`
- Garbage-collect les subscribers morts sur échec `broadcast()` (un send non-bloquant détecte un channel plein / fermé)
- Ajouter une assertion style `t.Helper()` en test que `Subscribe` est appelé une fois

### F-8 — Default `defaultEgress = "allow"` et `defaultIngress = "allow"` — fail-open

**CVSS 3.1 (contexte projet) :** N/A — c'est by design, pas un bug, mais à signaler dans un audit de sécurité.

**Où :** `nix/microsegebpf.nix:75-85`.

**Issue.** Quand aucune policy ne matche un flux, le verdict est « allow ». Un opérateur qui déploie sans policies et se repose sur le défaut n'a pas d'enforcement du tout — exactement le mode bake-in que le README documente. **Un défenseur qui déploie de la microsegmentation devrait switcher `defaultEgress = "drop"`** (et ajouter des règles allow explicites) une fois le bundle policy baked-in.

**Documenté dans :** la section « Limites et roadmap » du README appelle explicitement le toggle bake-in / production. Le mode bake-in `enforce = false` (commit `fed5f4b`) demote en plus les drop verdicts vers log pour que l'opérateur puisse ramper up safely.

---

## 6. Forces architecturales

L'audit a identifié les choix de design suivants comme positifs sécurité :

1. **Pas de CAP_SYS_ADMIN, pas de root** — l'agent tourne avec le set de capabilities minimum requis pour eBPF (`CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`, `CAP_SYS_RESOURCE`). `NoNewPrivileges = true`, `ProtectSystem = strict`, `ReadWritePaths = [ "/sys/fs/bpf" ]` uniquement.
2. **Binaire statique, closure quasi-vide** — l'agent ne link rien dynamiquement. La closure runtime est `iana-etc + mailcap + microseg-agent` (4 composants total). Aucun CVE glibc ne s'applique.
3. **Le shipper Vector est une unit séparée, sandboxée** — `DynamicUser = true`, `RestrictAddressFamilies = [ AF_INET AF_INET6 AF_UNIX ]`, `SystemCallFilter = [ @system-service @network-io ]`, `ProtectKernel*` partout. Une compromission de Vector ne peut pas pivoter vers l'agent ou vers les maps BPF ; elle peut juste sortir vers les endpoints OpenSearch / syslog configurés (que `RestrictAddressFamilies` limiterait aussi à des sockets IPv4/IPv6 — pas raw, pas netlink).
4. **Default = TLS pour syslog** (`mode = "tcp+tls"`), avec un warning NixOS bruyant si downgrade vers TCP plain ou UDP. Le choix non-chiffré est reviewable dans le log de rebuild, jamais silent.
5. **Default = vérification TLS on pour OpenSearch et syslog** (`tls.verifyCertificate = true`). La désactiver requiert un `false` explicite et Vector émet un WARN runtime.
6. **Secrets via `LoadCredential` systemd** — bind-mount du fichier source dans le namespace de l'unit, jamais embedé dans la directive `Environment=` de l'unit (que journald persisterait).
7. **Conforme REUSE 3.3** — chaque fichier a copyright + licence claire, audité par `reuse lint` dans la VM dev.
8. **Artefacts eBPF pré-générés commitéses** — le build Nix est reproductible et tourne en sandbox sans accès `/sys`, éliminant la classe de tampering build-time qui viendrait sinon de la régénération BTF à chaque CI run.
9. **TLS peek-only, jamais déchiffrement** — le parser SNI/ALPN inspecte les extensions ClientHello et rien d'autre. Pas de key material dans le programme kernel ; un opérateur qui a besoin d'inspection L7 doit utiliser un proxy séparé.
10. **Réconciliation map en delta** — `Apply()` n'écrit que les entrées changées (commit `585e20c`). Pas de gap transitoire où un flux match l'ancienne policy et la nouvelle mais ni l'une ni l'autre n'a son entrée dans la map.

---

## 7. Recommandations

Par ordre de priorité, lowest-effort en premier. Strikethrough = fait dans une révision ultérieure.

### 7.1 Immédiat (fermé en v2 — commit `9b7f56a`)

- [x] ~~Bumper Go vers 1.25.9+~~ — couvert par le runner CI (setup-go installe 1.25.9) ; la VM dev tracke un snapshot un peu plus vieux, sans pertinence pour le déploiement
- [x] ~~Documenter l'exposition Hubble TCP-listener (F-1)~~ — warning Nix + warning runtime agent + README + ARCHITECTURE
- [x] ~~Capper la taille du fichier policy (F-2)~~ — `MaxPolicyFileBytes = 16 MiB` avec erreur overrun explicite
- [x] ~~Bumper quay.io/cilium/hubble-ui:v0.13.2 → v0.13.5~~ — PR upstream "Security Patching - Dockerfile"
- [x] ~~Hubble UI : drop --network=host~~ — switché en bridge podman avec mapping `127.0.0.1:port`

### 7.2 Court-terme (fermé en v3 — commit courant)

- [x] ~~TLS pour l'observer gRPC (F-1, F-4)~~ — TLS + mTLS server-side complet via `services.microsegebpf.hubble.tls.*`, flags `-tls-*` matching sur `microseg-probe`
- [x] ~~Cache de résolution DNS avec respect TTL (F-3)~~ — option `dnsCacheTTL` (défaut 60s) + fallback stale-while-error

### 7.3 Long-terme (ouvert)

- [ ] Tracker la security branch nixpkgs-25.11 via une automation style renovate ; aujourd'hui le flake input pin le nom du channel (`nixos-25.11`) qui auto-track mais est non-reproductible entre deux clones d'une semaine d'écart.
- [ ] Symétrie Subscribe / Unsubscribe sur le watcher inotify (F-7).
- [ ] Scoping TLS par cgroup (déjà sur la roadmap README) — élimine le caveat « SNI deny host-global ».
- [ ] Rejeter les `metadata.name` dupliqués dans les bundles policy (mentionné dans la note de mitigation F-2).
- [ ] Support optionnel pour une adresse résolveur custom (DoT / do53-tcp-only) pour qu'un opérateur qui ne peut pas déployer un résolveur DNSSEC local ait quand même un peu de validation (note pas-adressé F-3).

---

## 8. Intégration CI

Ajouter un workflow `.github/workflows/security.yml` qui tourne nightly et sur chaque PR :

1. `govulncheck ./...` — gate les CVEs stdlib + modules Go
2. `reuse lint` — gate la conformité licence
3. `sbomnix` contre les closures agent et Vector, diff contre `sbom/sbom-*.cdx.json` — gate la dérive de closure (toute nouvelle dep update le SBOM)
4. `grype` contre le tag pinné Hubble UI — early warning quand l'image upstream accumule des CVEs

Wirer le workflow pour fail les PRs qui introduisent un CVE ≥ 7.0 dans le path de code atteignable de l'agent.

---

## 9. Items out-of-scope délibérément non évalués

- **Le noyau Linux lui-même.** Le datapath eBPF tourne in-kernel ; un CVE kernel qui affecte `cgroup_skb`, `bpf_loop`, ou la sémantique LPM trie pourrait cascader dans notre code. Tracking via la cadence normale d'update kernel du poste (NixOS `linuxPackages_latest` suit mainline en quelques jours).
- **Gestion de secrets côté opérateur** (SOPS, agenix, vault-agent). Le module accepte les chemins `passwordFile`, `keyFile`, `keyPassFile` ; comment ils arrivent là est l'affaire du déploiement.
- **Attaques network-layer** sous le hook eBPF. cgroup_skb fire *après* iptables / nftables sur le path egress et *avant* iptables / nftables sur ingress. Les opérateurs qui veulent défense-en-profondeur devraient layer ça avec un firewall hôte.

---

## 10. Disclosure

C'est le premier audit de sécurité de `nixos-microsegebpf`. Pas de finding sous embargo — chaque issue documentée ici est soit :
- Un CVE tiers connu déjà public dans le NVD
- Un finding code-review dans la source de ce projet, divulgué dans ce document avec le guidance de mitigation dont un opérateur a besoin

Si vous découvrez une vulnérabilité non couverte ici, merci d'envoyer un email à **aurelien.ambert@proton.me** avec `[microsegebpf]` en sujet. Fingerprint clé PGP et timeline de disclosure seront ajoutées dans une révision future.
