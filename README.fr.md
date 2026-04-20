# nixos-microsegebpf

[English](README.md) · [Français](README.fr.md)

**Microsegmentation eBPF pour postes de travail Linux, avec une couche
d'observabilité compatible Hubble.**

`nixos-microsegebpf` apporte le modèle de policy par identité de Cilium
sur une seule machine Linux. L'agent attache des programmes eBPF à la
racine du cgroupv2, fait correspondre le cgroup local de chaque paquet
à une policy YAML, drop ou laisse passer en conséquence, et émet des
événements de flux sur un serveur gRPC qui parle le même protocole
`cilium.observer.Observer` que Hubble — de sorte que la
[Hubble UI](https://github.com/cilium/hubble-ui) upstream peut afficher
en direct la carte des flux du poste, sans aucune ressource Kubernetes.

## Architecture en un coup d'œil

Le diagramme ci-dessous montre les quatre couches de confiance
(datapath eBPF kernel, agent userspace, services co-localisés
optionnels, plan de configuration + endpoints externes), comment un
paquet circule du hook cgroup_skb à travers les LPM tries jusqu'au
verdict, comment les flow events arrivent dans la Hubble UI et le
SOC, et où vit chaque surface de durcissement scorée par CVE.

```mermaid
%%{init: {'theme':'base', 'themeVariables': {
  'primaryColor':'#FFFFFF', 'primaryTextColor':'#0F172A',
  'primaryBorderColor':'#475569', 'lineColor':'#475569',
  'fontFamily':'monospace', 'fontSize':'13px'
}}}%%
flowchart TB

%% ───────── Kernel ─────────
subgraph KER["🛡 Noyau Linux — datapath eBPF (cgroup_skb)"]
  direction LR
  K1[cgroup_skb/egress<br/>chaque paquet sortant]
  K2[cgroup_skb/ingress<br/>chaque paquet entrant]
  K3[(LPM tries<br/>egress_v4/v6, ingress_v4/v6<br/>clé : cgroup_id, port, proto, ip)]
  K4[(tls_sni_lpm + tls_alpn_deny)]
  K5[Peeker TLS ClientHello<br/>SNI + ALPN via bpf_loop<br/>scratch per-CPU 256 octets]
  K6{Verdict<br/>SK_PASS / SK_DROP}
  K7[(Ring buffer 1 MiB)]
  K8[(map default_cfg<br/>enforce, tlsPorts, blockQuic)]
  K1 -- lookup --> K3
  K2 -- lookup --> K3
  K5 -- LPM inversé --> K4
  K3 --> K6
  K4 --> K6
  K6 -- flow event --> K7
end

%% ───────── Agent userspace ─────────
subgraph AG["⚙ microsegebpf-agent.service · CAP_BPF · NET_ADMIN · PERFMON"]
  direction LR
  A1[pkg/loader<br/>cilium/ebpf<br/>load .o → attach cgroupv2]
  A2[pkg/policy<br/>Map.Update delta<br/>cache DNS 60s + stale-while-error<br/>cap fichier 16 MiB]
  A3[pkg/identity<br/>walker cgroup<br/>inotify pub/sub Subscribe]
  A4[pkg/observer<br/>gRPC Hubble<br/>socket unix / TCP+TLS / mTLS]
  A6([Binaire Go statique · closure runtime 4 composants<br/>iana-etc · mailcap · agent · tzdata<br/>NoNewPrivileges · ProtectSystem strict · SystemCallFilter])
  A3 -- événements cgroup --> A2
  A3 -- événements cgroup --> A4
end
A1 -- attach + load --> K1
A1 -- ring read --> K7
A2 -- write delta --> K3
A2 -- write delta --> K4

%% ───────── Co-located optional services ─────────
subgraph OPT["🔌 Services co-localisés optionnels (chacun opt-in via le module NixOS)"]
  direction LR
  O1[microsegebpf-log-shipper.service<br/>Vector 0.52 · DynamicUser<br/>journald → parse_json → split → 4 sinks]
  O2[hubble-ui · OCI v0.13.5 podman<br/>volume /run/microseg<br/>bind 127.0.0.1:12000 only]
  O3[systemd-journald<br/>buffers stdout/stderr par boot<br/>curseur dans /var/lib/vector]
  O4[CLI microseg-probe<br/>-tls-ca/-cert/-key/-server-name]
  O3 --> O1
end
A4 -- gRPC<br/>unix ou TCP+TLS --> O2
A4 -- gRPC --> O4
AG -. stdout/stderr .-> O3

%% ───────── Configuration + external ─────────
subgraph EXT["🌐 Plan de configuration &amp; endpoints externes"]
  direction LR
  E1[/Flake GitOps + module NixOS<br/>services.microsegebpf.{enable, enforce,<br/>policies, hubble.tls, dnsCacheTTL,<br/>logs.opensearch, logs.syslog}/]
  E2[/Policy YAML<br/>règles : cidr | host<br/>selector : cgroupPath | systemdUnit<br/>tls.sniDeny / tls.alpnDeny<br/>8 baselines/]
  E3([👤 Opérateur])
  E4[Résolveur DNS<br/>système /etc/resolv.conf<br/>idéalement DNSSEC validating local]
  E5[(OpenSearch / SIEM<br/>index flows + index agent<br/>Vector elasticsearch sink)]
  E6[(SIEM syslog corp<br/>rsyslog · syslog-ng · Splunk · Wazuh<br/>port 6514 RFC 5425 TLS)]
end
E1 -- render flags --> AG
E2 -. -policy=… .-> A2
E3 -- ssh -L 12000 --> O2
E3 -- CLI inspect --> O4
A2 -. host: re-résolve .-> E4
O1 -. _bulk HTTPS .-> E5
O1 -. RFC 5425 TLS .-> E6

%% styles
classDef kernel fill:#DBEAFE,stroke:#1E3A8A,stroke-width:2px
classDef agent  fill:#D1FAE5,stroke:#065F46,stroke-width:2px
classDef opt    fill:#EDE9FE,stroke:#5B21B6,stroke-width:2px
classDef ext    fill:#FEF3C7,stroke:#92400E,stroke-width:2px
class KER kernel
class AG  agent
class OPT opt
class EXT ext
```

> **Frontières de confiance** — bordures pleines = processus /
> primitives kernel ; formes arrondies = documents de
> configuration ; cylindres = stores stateful (maps eBPF, journald,
> OpenSearch). Flèches pleines = paths in-process / kernel ;
> flèches pointillées = traversent le réseau ou la frontière de
> configuration on-disk. Chaque composant de la rangée optionnelle
> est **off par défaut** dans le module NixOS.

---

## À quoi ça sert

### Filtrage firewall local vs microsegmentation eBPF — la différence qui compte

Un **firewall local** classique (`iptables`, `nftables`, le firewall
hôte intégré au poste) filtre par **identité réseau** : IP source, IP
destination, port, protocole. Son modèle mental est un schéma réseau
avec des zones et des règles entre elles : « autoriser `10.0.0.0/24`
à joindre `10.0.0.5:443` ». Sur un poste de travail c'est grossier —
tous les processus de l'utilisateur partagent la même IP, donc tous
héritent de la même policy. Un onglet de navigateur compromis et un
`apt update` légitime sont identiques pour le firewall. Pire : deux
postes sur le même sous-réseau interne sont mutuellement joignables
sur tous les ports que le firewall local ne ferme pas explicitement,
ce qui est la précondition classique du **mouvement latéral** une
fois qu'un seul hôte est compromis.

La **microsegmentation eBPF** filtre par **identité de workload** :
quel processus, quel utilisateur, quelle unité systemd, quel cgroup.
Le modèle mental est une policy par application : « Firefox peut
joindre `*.corporate.com:443`, rien d'autre n'a le droit ». La même
destination derrière la même IP reçoit un verdict différent selon
*qui* la demande. Deux postes sur le même `/24` ne se font plus
confiance par défaut — l'agent de chaque poste applique son propre
moindre-privilège ingress et egress dans le noyau, même quand le
réseau sous-jacent leur permettrait de se parler.

`nixos-microsegebpf` te donne ce second modèle sur une seule machine
Linux, avec les identités naturelles du poste (id cgroupv2, unité
systemd, uid) au lieu des labels de pod Kubernetes que Cilium exige.

### Gestion centralisée via Nix, déployée à grande échelle

L'intérêt de livrer ce projet sous forme de module NixOS + flake est
que le workflow opérateur est strictement le même que pour n'importe
quel autre morceau de la configuration du poste :

  1. Le bundle de policies microseg pour **tout le parc** vit dans
     **un seul repo git**, exprimé en Nix. Pas de YAML à éditer
     poste par poste.
  2. Un changement de policy passe par **les mêmes gates de revue
     et de CI** que n'importe quel autre changement de
     configuration : `nix flake check` boote une VM NixOS, applique
     la nouvelle policy, et atteste le verdict drop dans le noyau
     avant que le changement ne touche un poste réel.
  3. Le rollout passe par l'outil de déploiement NixOS déjà utilisé
     par l'équipe (`nixos-rebuild switch`, `deploy-rs`, `colmena`,
     `morph`). systemd remarque que le chemin du fichier de policy
     dans `/nix/store` change, redémarre `microsegebpf-agent`, et
     les maps eBPF sont repeuplées en moins d'une seconde sur chaque
     poste.
  4. Le rollback est `nixos-rebuild --rollback` — la génération
     précédente de la policy est toujours dans le store.

Ça compte dans le **contexte de durcissement poste ANSSI**, où le
rationnel de la microsegmentation sur le *poste admin* est de priver
l'attaquant du mouvement latéral qu'il obtient gratuitement sur un
sous-réseau interne plat. Sans ça, deux options peu attractives :

  * **Microsegmentation côté réseau** (VLAN privé par hôte, NAC avec
    policy par MAC, mesh de firewalls internes) — coûteux à opérer,
    exige des changements switch / routeur / appliance,
    généralement hors de portée d'une petite équipe ops.
  * **Règles firewall par hôte éditées individuellement** — pas de
    cohérence, pas de trace de revue, et dès qu'un hôte dérive, le
    parc retombe à « tout interne est de confiance ».

`nixos-microsegebpf` aplatit le coût : l'enforcement tourne dans le
noyau de chaque poste (pas de nouvelle appliance à acheter ou
opérer), et le plan de management est un repo git de la même forme
et avec la même tooling que le reste de la configuration NixOS de
l'équipe. Le confinement de mouvement latéral grade ANSSI devient un
changement de configuration, pas un projet d'infrastructure.

### Cas d'usage concrets

| Objectif | À quoi ressemble la policy | Ce que ça défend |
|---|---|---|
| **Contenir un navigateur compromis** | `selector: { systemdUnit: "app-firefox-*.scope" }` + drop egress vers RFC1918 | Une extension navigateur weaponisée qui scan ou pivote sur des hôtes internes |
| **Forcer le DNS corporate** | `selector: { cgroupPath: /user.slice }` + drop TCP/UDP/53, /443, /853 vers les resolvers publics | Exfiltration par DNS-tunnel, contournement DoH/DoT du filtre corporate |
| **Restreindre SMTP au MTA** | `selector: { cgroupPath: / }` + autoriser TCP/25 uniquement vers le CIDR du relais | Un binaire malveillant utilisant un serveur SMTP en dur pour exfiltrer |
| **Verrouiller l'ingress sshd** | `selector: { systemdUnit: sshd.service }` + autoriser entrée uniquement depuis le CIDR du bastion | `sshd` exposé internet subissant du credential stuffing |
| **Bloquer des IP C2 connues** | `selector: { cgroupPath: / }` + drop egress vers une liste IP issue d'un feed threat-intel | Beaconing depuis un binaire malveillant déjà sur disque |
| **Tout auditer dans Hubble** | `enforce = false` + observe-only | Cartographier la surface réelle des flux du poste avant d'écrire la moindre règle drop |

### Différence avec ce que tu as déjà

| Tu as déjà... | Ce qui manque pour les cas ci-dessus | Ce que microseg-poste apporte |
|---|---|---|
| `nftables` / `iptables` | Les règles par processus exigent l'extension de match `cgroup` et ne connaissent pas nativement les noms d'unités systemd | Règles par unité systemd out of the box ; Hubble UI pour la visu |
| AppArmor / SELinux | Pas de notion de policy *de destination réseau* ; ils restreignent les arguments de syscall et les accès fichiers | Enforcement réseau au niveau paquet |
| Tetragon | L'enforcement est `SIGKILL` ou override de syscall → tue le processus. Brutal sur un desktop (session navigateur perdue) | `SK_DROP` au niveau paquet → la connexion échoue proprement, l'application continue |
| Cilium | Exige Kubernetes ; labels de pods pour l'identité | Pas de cluster, pas de K8s ; id de cgroup + unité systemd comme identité |
| OpenSnitch / Little Snitch | Interactif, prompts par connexion ; super pour usage perso, pas pour de l'enforcement style ANSSI | Policy déclarative YAML/Nix, GitOps-friendly, pas de prompts utilisateur |

### Quand ne **pas** utiliser ce projet

- **Serveur avec gros débit réseau.** `cgroup_skb` coûte quelques
  centaines de nanosecondes par paquet ; OK pour un poste, pas pour
  des serveurs 10 GbE+ — utiliser Cilium proper là-bas.
- **Tu veux filtrer par nom d'hôte** (`*.facebook.com`). Ce projet
  travaille sur des IP résolues et (bientôt) sur le SNI TLS. Pour du
  filtrage purement par nom d'hôte, coupler avec un outil de policy
  DNS.
- **Tu as besoin d'inspection L7** (bloquer des chemins HTTP
  spécifiques, parser des JWT, rate-limiter par endpoint API). C'est
  le travail d'un proxy L7 (Envoy, Traefik, NGINX). Microseg-poste
  reste délibérément en L3/L4.
- **Tu ne peux pas faire tourner un noyau ≥ 5.10.** Le point
  d'attache cgroup_skb et le type de map LPM_TRIE pré-datent ça,
  mais la fiabilité BTF / CO-RE commence vraiment à 5.10. Testé sur
  6.12.

---

## Pourquoi ce projet existe

Cilium et Hubble sont conçus pour des clusters Kubernetes. Leur modèle
d'identité repose sur les labels de pods, leur datapath s'attache aux
interfaces veth de pods, et Hubble UI s'attend à ce que les flux
proviennent d'un `hubble-relay` alimenté par les `cilium-agent` de
chaque nœud. Sur un poste de travail il n'y a ni pods, ni serveur API,
ni labels — Cilium ne s'applique donc pas.

[Tetragon](https://github.com/cilium/tetragon), l'extraction bare-metal
de Cilium par Isovalent, est ce qui s'en rapproche le plus : il charge
de l'eBPF sur un hôte, expose une CRD TracingPolicy et fonctionne sans
cluster. Mais Tetragon se limite délibérément à **l'observabilité de
sécurité runtime + l'enforcement au niveau syscall** (kprobe + `SIGKILL`
ou override de la valeur de retour). Il ne fournit pas de datapath
réseau : pas d'équivalent `bpf_lxc.c` / `bpf_host.c` dans le dépôt
Tetragon, pas de matching CIDR par LPM, pas de verdict drop par flux au
niveau paquet.

`nixos-microsegebpf` comble ce vide. Il fait ce que Cilium fait sur un
nœud Kubernetes — charger des programmes eBPF qui possèdent le chemin
des paquets, évaluer des policies sensibles à l'identité, émettre des
flux Hubble — mais avec les primitives d'identité naturelles du poste :

- l'**identifiant cgroupv2** de l'endpoint local (renvoyé nativement par
  `bpf_get_current_cgroup_id`)
- son **nom d'unité systemd**, dérivé du chemin du cgroup
  (`/user.slice/user-1000.slice/app.slice/firefox.service` →
  `firefox.service`)
- son **utilisateur propriétaire**, accessible par la même traversée

Une policy peut donc cibler « tout ce qui est lancé par Firefox » ou
« tout processus sous `user.slice` » de la même façon qu'une policy
Cilium cible un label de pod.

## Ce que l'outil fait concrètement

Une fois l'agent en marche, quatre choses se produisent à chaque
paquet :

1. **Le hook eBPF se déclenche.** `cgroup_skb/egress` (ou `/ingress`)
   attaché à la racine du cgroupv2 attrape le paquet juste avant qu'il
   ne parte sur le réseau (ou juste après son arrivée). Le handler lit
   les en-têtes IP/L4, demande au noyau à quel cgroup appartient le
   processus local, et construit une clé de lookup de policy.

2. **Lookup LPM.** L'agent maintient quatre maps
   `BPF_MAP_TYPE_LPM_TRIE` — `egress_v4`, `ingress_v4`, `egress_v6`,
   `ingress_v6`. La clé est un tuple packé
   `(cgroup_id, peer_port, protocol, peer_ip)`, avec le `prefix_len`
   LPM réglé pour que cgroup/port/protocol matchent exactement et que
   l'IP soit matchée jusqu'au préfixe CIDR configuré. Un miss retombe
   sur le verdict par défaut configurable.

3. **Verdict appliqué.** Le programme eBPF retourne `SK_DROP` (le
   noyau jette le paquet, le syscall voit `EPERM`) ou `SK_PASS`
   (forward normal). Pas d'aller-retour userspace, pas de proxy.

4. **Événement de flux émis.** Indépendamment du verdict, le programme
   réserve un enregistrement sur un ring buffer de 1 MiB avec le
   5-tuple, le verdict, l'identifiant de policy matché et le cgroup
   local. L'agent vide le ring buffer, décore chaque enregistrement
   avec le nom d'unité systemd issu d'un cache rafraîchi
   périodiquement, le convertit en protobuf `flow.Flow` Cilium, et le
   publie à chaque client Hubble connecté.

## À quoi ressemble une policy

```yaml
apiVersion: microseg.local/v1
kind: Policy
metadata:
  name: deny-public-dns-from-user-session
spec:
  selector:
    cgroupPath: /user.slice          # tout cgroup sous ce préfixe
  egress:
    - action: drop
      cidr: 1.1.1.0/24               # CIDR complet, matché en LPM
      ports: ["53", "443", "853"]    # ports exacts
      protocol: tcp
    - action: drop
      cidr: 2001:4860::/32           # IPv6 supporté nativement
      ports: ["443", "853"]
      protocol: tcp
    - action: drop
      cidr: 127.0.0.0/8
      ports: ["8000-8099"]           # ranges étendues côté serveur
      protocol: tcp
```

Une policy se réduit à : « pour chaque cgroup matchant le selector,
pousser N entrées dans la map LPM pour chaque direction ». Les
selectors peuvent cibler une **unité systemd par glob**
(`firefox.service`, `app-firefox-*.scope`) ou un **préfixe de chemin
de cgroup** (`/user.slice/user-1000.slice`).

## Matching TLS SNI / ALPN (peek-only)

Le filtrage par IP atteint sa limite sur les CDN : des milliers de
sites partagent les mêmes IP Cloudflare / Fastly / Akamai, et une
règle IP-seule soit sur-bloque (en cassant des destinations
légitimes), soit rate complètement (si l'IP de la destination change
entre l'écriture de la policy et le runtime). microsegebpf augmente
le datapath L3/L4 avec un parser TLS peek-only qui lit le nom d'hôte
SNI en clair et le premier identifiant de protocole ALPN dans le
ClientHello TLS, les hashe, et applique un verdict drop qui override
un allow IP-niveau.

**Pas de déchiffrement.** SNI et ALPN voyagent en clair dans le
ClientHello (le tout premier message du handshake TLS). Le parser
eBPF inspecte ces deux extensions et rien d'autre ; le reste de la
connexion lui est opaque.

### Schéma

```yaml
apiVersion: microseg.local/v1
kind: Policy
metadata:
  name: ban-doh-providers
spec:
  selector:
    cgroupPath: /                    # documentaire ; voir « Limites » ci-dessous
  tls:
    sniDeny:
      - "1.1.1.1"
      - "cloudflare-dns.com"
      - "dns.google"
    alpnDeny: []                     # voir warning ci-dessous
```

En Nix :

```nix
services.microsegebpf.policies = with microsegebpf.lib.policies.baselines; [
  (deny-sni { hostnames = [ "facebook.com" "tiktok.com" "x.com" ]; })
  (deny-alpn { protocols = [ "imap" "smtp" ]; })  # niche, voir ci-dessous
];
```

### Pourquoi ça compte : la démonstration SNI vs IP

```
$ curl https://cloudflare.com                                  # IPv4 chemin A
exit=28   (DROP — SNI matché 'cloudflare.com')

$ curl --resolve cloudflare.com:443:1.1.1.1 https://cloudflare.com   # IPv4 chemin B
exit=28   (DROP — SNI toujours 'cloudflare.com', IP peer différente)

$ curl https://example.com                                     # sans rapport
exit=0    (ALLOW)
```

Le même nom d'hôte derrière une IP différente, ou derrière un CDN
qu'on n'aurait pas pu prédire, est quand même attrapé.

### Matrice de couverture

Ce que le parser SNI/ALPN voit et ne voit pas, détaillé pour ne pas
être surpris :

| Protocole / contexte | Couvert ? | Pourquoi / pourquoi pas |
|---|---|---|
| HTTP/1.1 sur TLS, HTTP/2 sur TLS, gRPC sur TLS | ✅ | Le ClientHello TLS est identique quel que soit le L7 transporté par-dessus. |
| **HTTP/3 / QUIC** | ⚠ drop blanket seulement | Le ClientHello TLS de QUIC est chiffré avec des clés dérivées du Connection ID destination ; les dériver dans le noyau exige AES-128-CTR + AES-128-GCM qu'eBPF ne peut pas exécuter. Poser `services.microsegebpf.blockQuic = true` (flag CLI `-block-quic`) drop **tout** l'egress UDP vers tes `tlsPorts`. Les navigateurs retombent sur TCP/TLS, où le parser SNI matche. |
| **STARTTLS** (SMTP submission/587, IMAP/143, XMPP) | ❌ | Le handshake TLS suit un échange en clair (`STARTTLS\n`) et arrive en cours de stream. Notre parser n'inspecte que le premier paquet d'une connexion TCP fraîche. |
| TLS sur port non-standard | ✅ via config | Poser `services.microsegebpf.tlsPorts = [ 443 8443 4443 ];` (ou `-tls-ports=443,8443,4443`). Jusqu'à 8 ports. Le parser SNI se déclenche sur l'egress TCP vers chacun. |
| **SNI wildcard** (`*.example.com`) | ✅ | Implémenté via un trie LPM sur le hostname inversé (l'approche FQDN de Cilium). Le pattern stocke les octets de `.example.com` inversés avec un point terminal ; le lookup inverse le SNI on-wire et le trie sélectionne le préfixe matché le plus long. Seuls les wildcards à un seul niveau dans le label le plus à gauche sont supportés (`*.foo.com`, pas `evil*.foo.com` ni `foo.*.com`). |
| **L3/L4 par hostname FQDN** (`host: api.corp.example.com`) | ✅ | Utiliser `host:` au lieu de `cidr:` dans n'importe quelle règle egress/ingress. L'agent résout le FQDN en records A et AAAA via le résolveur système et installe une entrée `/32` (v4) ou `/128` (v6) par adresse résolue. La re-résolution se fait à chaque Apply (déclenché par cgroup-event ou ticker fallback), donc la règle suit le FQDN à mesure que ses records DNS changent. Les échecs de résolution loggent un warning et skip la règle pour ce tour. |

### Limites

- **TLS 1.3 ECH (Encrypted Client Hello)** est la menace long
  terme. Quand une destination négocie ECH (Cloudflare et Firefox
  ont déployé ça progressivement depuis 2024), le SNI est chiffré
  et le parser fail-open silencieusement. Horizon 2-3 ans avant que
  ça devienne le défaut.
- **ClientHello fragmenté.** Le parser inspecte la partie linéaire
  du premier segment TCP qui porte le ClientHello. En pratique,
  tout client courant fait tenir les extensions SNI/ALPN dans le
  premier segment (~512 octets typique, largement dans le MTU).
  Des clients pathologiques envoyant 16 KiB d'extensions PSK
  pourraient fragmenter — ceux-là passent.
- **Scoping par cgroup.** Le PoC indexe la map TLS uniquement sur
  le hash FNV-64 du nom d'hôte / chaîne ALPN. Les denies SNI sont
  donc globaux à l'hôte : chaque cgroup y est soumis, indépendamment
  du selector du policy doc qui les porte. Le champ selector au
  niveau de la policy est documentaire dans ce cas. Des règles TLS
  par cgroup exigent une clé `(cgroup_id, hash)` — follow-up
  raisonnable.
- **Première entrée ALPN uniquement.** Le walker inspecte
  uniquement le premier protocole de la liste ALPN. Suffisant pour
  attraper des beacons single-purpose (`h2`-only) ; un client
  malveillant envoyant `["h2", "x-evil"]` avec `x-evil` second
  passe.
- **Bloquer ALPN `h2` en blanket est un piège.** Presque
  tous les clients HTTPS modernes annoncent `h2`. Utiliser
  `alpnDeny` pour des bans protocolaires étroits (`imap`, `smtp`,
  identifiants custom) ou dans des déploiements air-gappés où la
  liste blanche protocolaire est courte.

## Recettes

Huit exemples concrets couvrant les formes les plus courantes de
durcissement poste. Les six premiers sont des fragments de
`services.microsegebpf.policies` à déposer dans le flake de
déploiement ; les deux derniers (centralisation des logs vers
OpenSearch et syslog) configurent la plomberie opérationnelle
autour de l'agent.

### Recette 1 — Forcer le résolveur DNS corporate

**Cas d'usage.** Tu fais tourner un résolveur DNS corporate (avec
logging, blocklists malware, zones internes). Tu ne veux pas qu'un
navigateur, un gestionnaire de paquets, ou un binaire compromis le
contourne en parlant directement au `1.1.1.1` de Cloudflare, ou pire,
en tunnelant via DoH (`https://1.1.1.1/dns-query`) ou DoT
(`tcp/853 vers 8.8.8.8`).

**Pourquoi ça compte.** Un chemin direct vers un résolveur public
contourne tout le filtrage, le logging et la détection corporate —
à la fois pour les violations de policy au quotidien et pour le C2
malware par DNS.

```nix
services.microsegebpf.policies = with microsegebpf.lib.policies; [
  # Drop DNS classique, DoT, DoH vers les résolveurs publics
  # bien connus. Le baseline embarque une liste IP+port curée pour
  # Cloudflare, Google, Quad9, OpenDNS, AdGuard.
  (baselines.deny-public-dns { })

  # Ceinture-et-bretelles : bloque aussi via SNI tout host se
  # faisant passer pour un fournisseur DoH sur une IP différente
  # (re-routage CDN, nouvelles IP pas encore dans le feed). Le
  # wildcard attrape les variantes hostées sur CDN type
  # resolver-dot1.dnscrypt.example.com.
  (mkPolicy {
    name = "deny-doh-providers-by-sni";
    selector = { cgroupPath = "/"; };
    sniDeny = [
      "cloudflare-dns.com"
      "*.cloudflare-dns.com"
      "dns.google"
      "*.dns.google"
      "dns.quad9.net"
      "*.quad9.net"
      "doh.opendns.com"
      "*.dnscrypt.org"
    ];
  })
];
```

**Comment ça marche.**

  - `baselines.deny-public-dns {}` bloque **TCP et UDP** vers les
    IP des résolveurs publics majeurs sur les ports `53`, `443`, et
    `853` (couvre DNS clair, DoH, DoT). Indexé par défaut sur le
    selector `/user.slice` ; passer `cgroupPath = "/"` pour étendre
    aux services système aussi.
  - Le `mkPolicy` custom ajoute une **deny list TLS SNI** — même
    si l'IP d'une destination n'est pas dans notre liste, un
    handshake TLS annonçant le SNI d'un fournisseur DoH connu est
    drop avant la fin du ClientHello.
  - Les entries wildcard (`*.cloudflare-dns.com`) attrapent les
    variantes CDN-edge sans énumérer chaque PoP.

**Variations.**

  - Pour autoriser DoH uniquement vers **ton** résolveur corporate,
    le passer en `extraIPv4` / `extraIPv6` à `deny-public-dns` pour
    garder la baseline blocklist tout en exemptant ton IP via une
    entrée `allow` explicite dans un `mkPolicy`.

### Recette 2 — Containment navigateur : zéro accès réseau interne

**Cas d'usage.** Firefox / Chromium exécute du JavaScript non
sécurisé tous les jours. Une extension weaponisée ou un RCE 0-day
ne devrait pas pouvoir scan le `10.0.0.0/8` corporate, taper le
Confluence interne sur le port 80, ou monter des attaques SMB
latérales.

**Pourquoi ça compte.** C'est le durcissement poste ANSSI à plus
fort impact unitaire : ça convertit « navigateur compromis » de
« l'attaquant voit maintenant le réseau interne » en
« l'attaquant a un process navigateur sandboxé sans handle réseau
exploitable vers le LAN ».

```nix
services.microsegebpf.policies = with microsegebpf.lib.policies; [
  # Le baseline drop l'egress depuis /user.slice vers RFC1918 sur
  # les ports les plus attaqués (SSH, HTTP, HTTPS, SMB, RDP,
  # alt-HTTP).
  (baselines.deny-rfc1918-from-user-session { })

  # Carve-out par unité pour le SSH helpdesk IT (l'utilisateur a
  # légitimement besoin de ssh vers le bastion).
  (mkPolicy {
    name = "allow-bastion-ssh-from-user";
    selector = { cgroupPath = "/user.slice"; };
    egress = [
      (allow {
        cidr = "10.0.0.42/32";   # IP du bastion
        ports = [ "22" ];
        protocol = "tcp";
      })
    ];
  })
];
```

**Comment ça marche.**

  - Le baseline drop six ports courants sur les trois ranges
    RFC1918. Onglets navigateur, clients mail, tout ce qui est
    sous `/user.slice` ne peut pas joindre les services internes
    sur ces ports.
  - Le carve-out est un `allow` plus prioritaire qui ré-active le
    chemin légitime. **Précédence** : le trie LPM pioche le match
    de préfixe le plus long par tuple `(cgroup, port, proto)`,
    donc l'entrée `/32` gagne sur le drop `/8` pour `10.0.0.42:22`.
  - L'IO réseau du navigateur vers internet public (`0.0.0.0/0`
    moins RFC1918) n'est pas affectée — pas de firewall egress
    implicite introduit.

**Variations.**

  - Pour étendre à tous les sous-cgroups d'une unité systemd
    spécifique : `selector = { systemdUnit = "app-firefox-*.scope"; }`.
  - Pour Chromium sans isolation par-onglet, switcher
    `cgroupPath = "/user.slice"` à un selector plus serré contre
    le nom de scope spécifique de Chromium.

### Recette 3 — Verrouiller SSH au bastion uniquement

**Cas d'usage.** Les postes de travail prod exposent `sshd` pour
incident response, mais seul le bastion corporate à `10.0.0.42`
devrait jamais l'atteindre. Un `sshd` exposé internet est un aimant
à credential stuffing, le poste devrait refuser SSH de toute autre
source même si un firewall mal configuré laisse accidentellement
passer les paquets.

```nix
services.microsegebpf.policies = with microsegebpf.lib.policies; [
  (baselines.sshd-restrict { allowFrom = "10.0.0.42/32"; })
];
```

**Comment ça marche.**

  - `selector = { systemdUnit = "sshd.service"; }` (posé dans le
    baseline) cible le cgroup que systemd crée pour `sshd`.
  - Le baseline émet une seule règle `ingress` :
    `allow { cidr = allowFrom; ports = [ "22" ]; protocol = "tcp"; }`.
    Sans règle `drop` listée et avec `defaultIngress = "drop"` posé
    sur le module policy, toute autre source est rejetée par
    défaut.
  - **Tu dois poser `services.microsegebpf.defaultIngress = "drop"`
    au niveau module** pour que ça morde — sinon le miss tombe sur
    default-allow.

**Variations.**

  - Pour plusieurs IP bastion : passer un `/24` (`"10.0.0.0/24"`)
    ou empiler plusieurs `mkPolicy` ajoutant chacun une IP.
  - Pour une paire bastion HA sur des ports différents, drop le
    baseline et utiliser `mkPolicy` directement avec deux règles
    `ingress`.

### Recette 4 — SMTP sortant uniquement via le relais corporate

**Cas d'usage.** Un binaire compromis essayant d'exfiltrer via
SMTP direct vers un mail server en dur doit échouer. Le chemin
légitime est via le MTA corporate (typiquement
`smtp-relay.corp:25`).

```nix
services.microsegebpf.policies = with microsegebpf.lib.policies; [
  (baselines.smtp-relay-only { relayCIDR = "10.0.1.10/32"; port = "25"; })
];
```

**Comment ça marche.**

  - `selector = { cgroupPath = "/"; }` — s'applique à tout cgroup
    de l'hôte (services système et processus user pareil).
  - Deux règles dans l'ordre de précédence (LPM, plus long match
    gagne) :
    1. `allow` vers `10.0.1.10/32` sur port 25 (`/32` = 32 bits préfixe)
    2. `drop`  vers `0.0.0.0/0` sur port 25 (`/0` = 0 bits préfixe)
  - Le `/32` du relais bat toujours le catch-all `/0`, donc le mail
    légitime passe ; tout le reste sur port 25 est rejeté.

**Variations.**

  - Pour SMTPS sur 465 ou submission sur 587, passer `port = "465"`
    ou `port = "587"` et empiler deux policies.
  - Pour exempter une unité systemd spécifique (ex.
    `postfix.service`) du drop, ajouter un `mkPolicy` avec
    `selector = { systemdUnit = "postfix.service"; }` et un `allow`
    explicite vers `0.0.0.0/0:25` — son match style cgroup `/32`
    prend la précédence.

### Recette 5 — Bloquer les réseaux sociaux via wildcards SNI

**Cas d'usage.** Politique de conformité / acceptable use bannit
l'accès en heures de travail à TikTok, Facebook, Instagram. Le
filtrage IP est futile (CDN-hosté, IP rotates constamment), mais
le matching SNI attrape chaque edge CDN qui sert la marque.

```nix
services.microsegebpf.policies = with microsegebpf.lib.policies; [
  (mkPolicy {
    name = "deny-social-media-sni";
    selector = { cgroupPath = "/user.slice"; };
    sniDeny = [
      "facebook.com"
      "*.facebook.com"
      "fbcdn.net"
      "*.fbcdn.net"
      "instagram.com"
      "*.instagram.com"
      "tiktok.com"
      "*.tiktok.com"
      "*.tiktokcdn.com"
      "x.com"
      "*.x.com"
      "twitter.com"      # redirection legacy
      "*.twitter.com"
    ];
  })

  # Forcer fallback QUIC pour que le matcher SNI se déclenche
  # vraiment. Sans ce switch, les navigateurs vont chercher
  # tiktok.com tranquillement en HTTP/3 (UDP) et notre parser
  # TCP-only ne voit jamais le SNI.
];

services.microsegebpf.blockQuic = true;
```

**Comment ça marche.**

  - `*.facebook.com` matche tous les sous-domaines (`m.facebook.com`,
    `web.facebook.com`, `static.xx.fbcdn.net`, ...). À combiner
    avec le `facebook.com` nu pour attraper aussi l'apex.
  - Plusieurs sites dans une même policy = juste une liste plus
    longue — le trie LPM scale à des milliers d'entrées avec un
    lookup en O(longueur-string).
  - `services.microsegebpf.blockQuic = true` est **essentiel** ici.
    Le ClientHello TLS de HTTP/3 est chiffré ; on ne peut pas
    peeker le SNI sur UDP/443. Faire échouer QUIC force les
    navigateurs à retomber sur TCP/443 où le parser SNI fait son
    job.

**Variations.**

  - Pour une approche allow-list (n'autoriser que `*.corporate.com`),
    inverser : poser `defaultEgress = "drop"` et écrire des
    `mkPolicy` avec règles `egress` `allow` pour les destinations
    qu'on veut permettre. Le matching SNI tout seul est une
    feature *deny-only* (pas d'allow override côté SNI ; le
    verdict niveau IP est la source de vérité).

### Recette 6 — Combiner durcissement port TLS + intégration threat-feed

**Cas d'usage.** Tu consommes un feed threat-intel quotidien (liste
d'IP connues mauvaises servant du C2 sur HTTPS ou ports TLS
inhabituels) et tu veux que microsegebpf l'enforce sans réinventer
le pipeline de déploiement.

```nix
let
  # Pulled au moment du déploiement par l'étape CI qui build le
  # closure du poste. L'IO doit se faire au temps de *build* (Nix
  # est hermétique au eval), donc une dérivation fetcher séparée
  # alimente la liste.
  threatFeed = builtins.fromJSON (builtins.readFile ./threat-ips.json);
in
{
  services.microsegebpf = {
    enable = true;
    enforce = true;

    # Traiter 443, 8443, et un port VPN corporate custom comme
    # TLS-bearing. Le parser SNI se déclenche sur l'egress TCP vers
    # n'importe lequel.
    tlsPorts = [ 443 8443 4443 ];

    # Drop QUIC blanket pour que l'enforcement SNI ne soit pas
    # contourné via HTTP/3.
    blockQuic = true;

    policies = with microsegebpf.lib.policies; [
      # Drop l'egress vers chaque IP du feed, sur les mêmes ports
      # TLS-bearing. Le feed IP est le bloqueur précis ; le check
      # SNI ci-dessous attrape l'infrastructure re-hostée.
      (baselines.deny-threat-feed {
        ips = map (ip: "${ip}/32") threatFeed.ips;
        ports = [ "443" "8443" "4443" ];
      })

      # Feed côté domaine (vendor différent, surface de menace
      # différente).
      (mkPolicy {
        name = "deny-threat-feed-sni";
        selector = { cgroupPath = "/"; };
        sniDeny = threatFeed.domains;   # mix exact + wildcard
      })
    ];

    hubble.ui.enable = true;   # voir ce qui se fait drop, en temps réel
  };
}
```

**Comment ça marche.**

  - `tlsPorts = [ 443 8443 4443 ]` étend le parser SNI pour qu'il
    se déclenche sur un port non-standard que le VPN corporate
    utilise. À la fois le matching SNI et `blockQuic` honorent
    cette liste.
  - Les IP du feed threat vont dans le LPM L3/L4 standard (couvert
    par `deny-threat-feed`) ; leurs hostnames vont dans le LPM SNI
    (couvert par le `mkPolicy` custom). Chaque couche seule attrape
    la plupart des beacons ; ensemble elles couvrent
    respectivement la rotation d'IP et la rotation de domaine.
  - `enforce = true` active les drops. Combiner avec
    `emitAllowEvents = false` (le réglage prod) pour garder le
    bruit Hubble bas.

**Variations.**

  - Pour un feed mis à jour plus souvent qu'à chaque rebuild
    NixOS, le fetch via timer systemd dans
    `/etc/microsegebpf/threat.yaml` et poser
    `services.microsegebpf.policies = [ (builtins.readFile
    "/etc/microsegebpf/threat.yaml") ]`. Le watcher inotify de
    l'agent capte les changements en ~250 ms.
  - Construire une dérivation nix minimale qui fetch le feed au
    build time (avec `pkgs.fetchurl` + hash) pour que le closure
    soit pleinement reproductible — le trade-off est un rebuild
    par mise à jour de feed.

### Recette 7 — Centralisation des logs vers OpenSearch

**Cas d'usage.** Un poste qui drop un flux malveillant à 03:14
heure locale ne devrait pas obliger un analyste à se SSH dessus
pour grepper journald et comprendre. Tu pousses chaque flow event
et chaque log control-plane dans un cluster OpenSearch parc-large
— exactement là où le SOC regarde déjà — et l'investigation du
lendemain matin devient une requête Kibana / OpenSearch
Dashboards, plus une expédition forensique.

**Pourquoi ça compte.** Le journald local va bien pour un poste
mais s'effondre à l'échelle parc : pas de corrélation cross-host,
pas de rétention au-delà du budget disque du poste, pas de hook
d'alerting. La Hubble UI est super pour de l'exploration
interactive de flux mais elle est éphémère et host-locale aussi.
Un store de logs central résout les trois : recherche cross-host,
rétention semaines-à-mois, et alerting qui se déclenche sur une
règle Sigma / Wazuh / OSSEC quand le même SNI C2 se fait drop sur
trois postes en cinq minutes.

```nix
services.microsegebpf = {
  enable = true;
  # ... ton bloc policy + observabilité habituel ...

  logs.opensearch = {
    enable = true;

    # N'importe quel nœud du cluster ; Vector route en interne
    # vers le bulk endpoint.
    endpoint = "https://opensearch.corp.local:9200";

    # Indices quotidiens — l'idiome OpenSearch pour les
    # time-series. Les tokens strftime sont expandus par Vector
    # à l'écriture.
    indexFlows = "microseg-flows-%Y.%m.%d";
    indexAgent = "microseg-agent-%Y.%m.%d";

    # Auth basique (obligatoire en prod). Le mot de passe est lu
    # par systemd depuis le fichier au démarrage et passé à
    # Vector via LoadCredential — jamais en ligne de commande,
    # jamais en clair dans l'environnement de l'unité.
    auth.user = "microseg-shipper";
    auth.passwordFile = "/run/keys/opensearch-microseg.pwd";

    # Pinning TLS sur la CA corporate. verifyCertificate=false
    # uniquement en lab — le warning du sink journald est
    # bruyant pour une bonne raison.
    tls.caFile = "/etc/ssl/certs/corp-internal-ca.pem";
  };
};
```

**Comment ça marche.**

  - L'agent **ne parle pas OpenSearch directement.** Il écrit du
    JSON structuré sur stdout (une ligne par flow event) et
    stderr (records slog control-plane). systemd capte les deux
    dans journald avec `_SYSTEMD_UNIT=microsegebpf-agent.service`.
  - Le module active une seconde unité systemd
    (`microsegebpf-log-shipper.service`) qui fait tourner
    [Vector](https://vector.dev) sous `DynamicUser=true`. La
    config Vector est générée par Nix sous forme de fichier JSON
    dans le store, donc reproductible et reviewable comme partie
    du diff de closure NixOS.
  - Le pipeline Vector a quatre nœuds :
    1. `sources.microseg_journal` — source `journald` filtrée
       sur l'unité de l'agent uniquement (`include_units` =
       `[ "microsegebpf-agent.service" ]`),
       `current_boot_only = true`.
    2. `transforms.microseg_parse` — `remap` VRL qui décode
       `.message` en JSON et merge les champs parsés à la
       racine de l'event. Les lignes non-JSON passent inchangées.
    3. `transforms.microseg_filter_{flows,agent}` — deux
       transforms `filter` qui splittent sur `exists(.verdict)`
       pour que les flow events et les records slog atterrissent
       dans des indices séparés.
    4. `sinks.opensearch_{flows,agent}` — deux sinks
       `elasticsearch` (le wire protocol Elasticsearch est le
       même qu'OpenSearch) qui écrivent dans les indices
       configurés en mode bulk.
  - L'unité shipper est sandboxée : `DynamicUser=true`,
    `ProtectSystem=strict`, `RestrictAddressFamilies` limité à
    `AF_INET/AF_INET6/AF_UNIX`, syscall filter `@system-service`
    + `@network-io`. Elle a juste besoin d'egress réseau vers
    OpenSearch et d'accès lecture journald (accordé via
    `SupplementaryGroups = [ "systemd-journal" ]`).
  - **Le découplage compte.** Si le cluster OpenSearch est down,
    Vector retry avec backoff exponentiel — l'agent et son
    datapath eBPF continuent. Si l'unité shipper crash, journald
    continue de buffer et Vector reprend où le curseur s'était
    arrêté au redémarrage. Il n'y a aucun chemin où une panne du
    pipeline de logs fait tomber l'enforcement.

**Variations.**

  - **Ajouter des champs à la source** (par ex. tagger chaque
    event avec le hostname du poste et la zone ANSSI) — utiliser
    `extraSettings` pour insérer un autre `remap` entre
    `microseg_parse` et les filtres :
    ```nix
    services.microsegebpf.logs.opensearch.extraSettings = {
      transforms.add_zone = {
        type = "remap";
        inputs = [ "microseg_parse" ];
        source = ''
          .anssi_zone = "poste-admin"
          .hostname = get_hostname!()
        '';
      };
      transforms.microseg_filter_flows.inputs = [ "add_zone" ];
      transforms.microseg_filter_agent.inputs = [ "add_zone" ];
    };
    ```
  - **Cluster différent par stream** (archive froide vs SOC
    chaud) — override un des sinks via `extraSettings` pour
    pointer sur un second endpoint avec une auth différente.
  - **Buffering disque** pour des liens WAN peu fiables — poser
    `extraSettings.sinks.opensearch_flows.buffer = { type =
    "disk"; max_size = 268435456; }` (256 MiB de cap). Le
    `data_dir = /var/lib/vector` est déjà câblé (avec
    `StateDirectory = "vector"` pour que `DynamicUser` continue
    de marcher).
  - **Garder un index OpenSearch par poste** en templatant le
    nom d'index avec le host : `indexFlows = "microseg-flows-
    \${HOSTNAME}-%Y.%m.%d";` (Vector expand les variables d'env
    dans le template d'index ; systemd injecte déjà HOSTNAME
    dans l'environnement de l'unité).

### Recette 8 — Forwarding syslog centralisé (RFC 5424 sur TLS)

**Cas d'usage.** Ton SOC a un SIEM (Splunk, Wazuh, ELK, IBM
QRadar, Microsoft Sentinel, …) qui ingère en syslog. Tu veux
que chaque flow event et chaque log control-plane de l'agent y
atterrisse avec le bon code de facility, pour que les pipelines
de parsing et d'alerting du SIEM fassent leur boulot dès le
premier jour.

**Pourquoi ça compte.** OpenSearch est super pour la recherche
ad-hoc mais le workflow incident du SOC passe probablement par
le SIEM : règles de corrélation, intégration ticketing, mapping
MITRE ATT&CK, paging on-call. Un SIEM qui sait déjà quoi faire
d'un `local4.warning` venant d'un poste NixOS s'onboarde plus
vite qu'un cluster OpenSearch tout neuf que personne n'est
d'astreinte sur.

**Pourquoi TLS.** Les flow events nomment les postes qui
droppent du trafic vers des destinations spécifiques sur des
ports spécifiques — exactement l'inventaire qu'un attaquant
déjà à l'intérieur veut. Le syslog UDP/514 en clair laisse
fuiter tout ça à n'importe quel passif sur le chemin. Le syslog-
sur-TLS RFC 5425 (port 6514) est le défaut moderne ; le module
défaut `mode = "tcp+tls"` et émet un warning au déploiement si
tu downgrade en UDP ou TCP clair.

```nix
services.microsegebpf = {
  enable = true;
  # ... ton bloc policy + observabilité habituel ...

  logs.syslog = {
    enable = true;

    # Collecteur SIEM. Le port 6514 est l'assignation IANA pour
    # syslog-over-TLS (RFC 5425). Vector se connecte directement
    # — pas de relais rsyslog ou syslog-ng entre les deux.
    endpoint = "siem.corp.local:6514";

    # Défaut ; on l'écrit explicitement pour que l'intention
    # soit reviewable.
    mode = "tcp+tls";

    # Champ APP-NAME du header RFC 5424. Les SIEMs route
    # dessus — court (<= 48 chars ASCII) et stable.
    appName = "microsegebpf";

    # Facilities. `local4` est une convention SIEM courante
    # pour les logs réseau security-relevant ; `daemon` est le
    # bucket canonique pour le control-plane de service.
    facilityFlows = "local4";
    facilityAgent = "daemon";

    # Pinning de la CA du SIEM. Pour mTLS, ajouter aussi
    # certFile + keyFile ; la clé est chargée via systemd
    # LoadCredential donc elle peut vivre sur un chemin que le
    # dynamic user ne peut pas lire directement (ex.
    # /etc/ssl/private mode 0640 root:ssl-cert).
    tls = {
      caFile  = "/etc/ssl/certs/corp-internal-ca.pem";
      certFile = "/etc/ssl/certs/microseg-client.pem";   # mTLS, optionnel
      keyFile  = "/etc/ssl/private/microseg-client.key"; # mTLS, optionnel
      # keyPassFile = "/run/keys/microseg-key-pass";     # si chiffrée
      verifyCertificate = true;
      verifyHostname    = true;
    };
  };
};
```

**Comment ça marche.**

  - Le module wire un pipeline Vector à côté (ou à la place) de
    celui pour OpenSearch — même `microsegebpf-log-shipper.service`,
    même source journald, mêmes transforms parse + filter. Deux
    transforms `remap` supplémentaires formattent chaque stream
    en RFC 5424 :
    ```
    <PRI>1 TIMESTAMP HOSTNAME APP-NAME - - - JSON-BODY
    ```
    `PRI = facility * 8 + severity`. La sévérité est calculée
    par event depuis le `.level` slog (stream agent) ou le
    `.verdict` (stream flow) : drop → 4 (warning), log → 5
    (notice), allow → 6 (info) ; ERROR → 3, WARN → 4, INFO → 6,
    DEBUG → 7.
  - Deux sinks `socket` écrivent vers l'endpoint configuré en
    TCP+TLS avec framing newline-delimited (compatible avec
    rsyslog `imtcp`, syslog-ng `network()`, Splunk HEC syslog,
    le listener port 6514 de Wazuh).
  - Sur le wire, trois events exemple ressemblent à :
    ```
    <164>1 2026-04-20T07:53:10.457337Z host microsegebpf - - - {"verdict":"drop","src":"10.0.0.1:443","dst":"1.1.1.1:443","unit":"firefox.service",...}
    <165>1 2026-04-20T07:53:10.457355Z host microsegebpf - - - {"verdict":"log","src":"10.0.0.1:53","dst":"9.9.9.9:53","unit":"dnsmasq.service",...}
    <166>1 2026-04-20T07:53:10.457362Z host microsegebpf - - - {"verdict":"allow","src":"10.0.0.1:80","dst":"8.8.8.8:80","unit":"sshd.service",...}
    ```
    164 = local4(20) * 8 + warning(4) ; 165 = local4 + notice ;
    166 = local4 + info. Les SIEMs qui route uniquement sur le
    PRI vont funneler les drops vers un bucket plus prioritaire
    sans le moindre parsing custom.
  - **Le découplage est le même que pour le shipper OpenSearch.**
    Handshake TLS qui rate ou SIEM down → Vector retry avec
    backoff, l'agent et le datapath eBPF continuent à enforcer.
    journald continue de buffer jusqu'à ce que le curseur (dans
    `/var/lib/vector/`) rattrape.

**Variations.**

  - **OpenSearch ET syslog en même temps** (déploiement SIEM
    typique) : activer les deux blocs d'options. Ils partagent
    le même process Vector dans
    `microsegebpf-log-shipper.service` — un seul process,
    quatre sinks (deux ES bulk + deux syslog socket).
  - **mTLS** (le SIEM authentifie le poste) : poser
    `tls.certFile`, `tls.keyFile` (et `tls.keyPassFile` si la
    clé est chiffrée). La clé privée est bind-mountée dans
    l'unité via systemd `LoadCredential` depuis le chemin de
    secret-management que tu utilises (SOPS, agenix, template
    vault-agent).
  - **SIEMs différents par stream** (un pour les verdicts, un
    pour les logs d'audit chez un autre vendor) : utiliser
    `extraSettings` pour override `sinks.syslog_flows.address`
    en gardant le `sinks.syslog_agent` par défaut pointé sur
    `endpoint`.
  - **Framing strict octet-counting RFC 5425** (certains
    collecteurs IBM / legacy enterprise l'exigent) : poser
    `framing = "bytes"` et ajouter un transform VRL via
    `extraSettings` qui prepend la longueur ASCII décimale +
    espace à chaque `.message`. La plupart des collecteurs
    modernes (rsyslog, syslog-ng, Splunk, Wazuh) acceptent le
    défaut `newline_delimited` donc t'en auras rarement
    besoin.
  - **TCP plain / UDP legacy** (lab, segment on-prem de
    confiance, ou phase de transition) : poser `mode = "tcp"`
    ou `mode = "udp"`. Le module émet un warning NixOS au
    moment de l'eval, le choix est donc explicite et reviewable
    dans le log de rebuild.

## L'intégration Hubble

Hubble UI est une application React qui se connecte à un endpoint gRPC
parlant
[`observer.proto`](https://github.com/cilium/cilium/blob/main/api/v1/observer/observer.proto).
Elle appelle quatre RPC au démarrage :

| RPC | Ce que renvoie nixos-microsegebpf |
|---|---|
| `ServerStatus` | Nombre de flux bufferisés, « 1 nœud connecté » (cet hôte), uptime |
| `GetNodes` | Une entrée `Node` avec le hostname local et `NODE_CONNECTED` |
| `GetFlows(stream)` | Un replay du ring de flux récents, puis tail live indéfini |
| `GetNamespaces` | Vide (on ne modélise pas les namespaces K8s) |

Chaque flux est un vrai protobuf `flow.Flow` avec :

- **IP** : source, destination, famille IPv4 ou IPv6
- **Layer4** : port source/destination TCP ou UDP
- **Source / Destination Endpoint** : quand le côté local est la source
  (egress), `Source` porte `cluster_name=host`, l'unité systemd comme
  `pod_name`, et des labels comme `microseg.unit=firefox.service`,
  `microseg.cgroup_id=12345`. Le côté distant devient un endpoint
  `world`. En ingress les rôles sont inversés.
- **Verdict** : `FORWARDED`, `DROPPED` (avec
  `DropReason=POLICY_DENIED`), ou `AUDIT`
- **TrafficDirection** : `INGRESS` ou `EGRESS`

Résultat : la Hubble UI upstream non modifiée affiche la carte des
flux du poste exactement comme si les cgroups locaux étaient des pods
Cilium. Service map, journal des flux, visualisation des drops — tout
fonctionne tel quel.

Un petit CLI compagnon, `microseg-probe`, appelle les mêmes RPC en
ligne de commande pour de l'inspection sans interface :

```
$ microseg-probe -limit=10
=== ServerStatus ===
  Version:        nixos-microsegebpf/0.1 (hubble-compat)
  NumFlows:       40 / 4096
  ConnectedNodes: 1
=== GetFlows (limit=10) ===
  DROPPED    EGRESS  10.0.2.15:52606 -> 1.1.1.1:443  src=host/session-50.scope dst=world/ policy=1
  FORWARDED  EGRESS  10.0.2.15:22 -> 10.0.2.2:47861  src=host/sshd.service dst=world/ policy=0
  ...
```

### Sécuriser l'observer gRPC avec TLS / mTLS

Le listener par défaut (`unix:/run/microseg/hubble.sock`, mode
0750 via `RuntimeDirectoryMode`) est restreint à root par le
noyau — pas besoin d'authentification de transport. **Un
listener TCP est une autre histoire :** chaque flow event que
l'agent observe (5-tuples + SNI) est streamé à n'importe qui qui
peut se connecter. Si tu as besoin de consommer les flux depuis
l'extérieur du poste, câble TLS — et pour la prod, mTLS.

```nix
services.microsegebpf.hubble = {
  listen = "0.0.0.0:50051";        # ou 127.0.0.1:50051 + tunnel SSH

  tls = {
    certFile          = "/etc/ssl/certs/microseg-server.pem";
    keyFile           = "/etc/ssl/private/microseg-server.key";
    clientCAFile      = "/etc/ssl/certs/microseg-clients-ca.pem";  # mTLS
    requireClientCert = true;                                       # mTLS hard-on
  };
};
```

Sans `certFile` + `keyFile`, le module émet un warning au moment
de l'évaluation nommant l'exposition cleartext (et l'agent émet
une ligne slog WARN au démarrage, miroir du message Nix-time).
Le CLI `microseg-probe` mirrore les mêmes options TLS
(`-tls-ca`, `-tls-cert`, `-tls-key`, `-tls-server-name`,
`-tls-insecure`) pour qu'un opérateur puisse vérifier
end-to-end :

```sh
microseg-probe -addr=corp-host:50051 \
  -tls-ca=/etc/ssl/certs/corp-ca.pem \
  -tls-cert=/etc/ssl/certs/operator.pem \
  -tls-key=/etc/ssl/private/operator.key \
  -tls-server-name=corp-host \
  -limit=10 -follow
```

### Cache de résolution FQDN

Les règles `host:` re-résolvent le nom DNS à chaque tick Apply.
Pour cap la fenêtre d'attaque resolver-poisoning — une réponse
DNS malveillante flippe l'entrée LPM `/32` entre deux ticks
Apply — l'agent cache les résultats pour
`services.microsegebpf.dnsCacheTTL` (défaut `60s`). Une
re-résolution échouée retombe sur la dernière réponse known-good
pour qu'une panne résolveur transitoire ne drop pas une règle
FQDN précédemment validée. Voir
[SECURITY-AUDIT.md §F-3](SECURITY-AUDIT.md) pour le threat model.

## Build

### Workflow de développement

```sh
cd nixos-microsegebpf
nix-shell --run 'make build'
sudo ./bin/microseg-agent -policy=examples/policy.yaml
```

Le `nix-shell` apporte Go 1.25, clang 21, llvm 21, bpftool 7, libbpf,
protoc, rsync. `make build` lance `bpftool` pour extraire le BTF du
noyau courant vers `bpf/vmlinux.h`, appelle `bpf2go` pour compiler
`bpf/microseg.c` et générer les bindings Go, puis `go build` produit
le binaire statique `bin/microseg-agent`.

### Build Nix reproductible

```sh
nix-build
sudo ./result/bin/microseg-agent -policy=examples/policy.yaml
```

`vendorHash` est figé dans `nix/package.nix` ; à recalculer quand
`go.mod` change :

```sh
nix-build 2>&1 | grep "got:" | awk '{print $2}'
# coller dans nix/package.nix
```

Le build Nix attend que `bpf/microseg_bpfel.{go,o}` et `bpf/vmlinux.h`
soient pré-générés (lancer `make generate` une fois, en dehors du
sandbox Nix, avant `nix-build`). Raison : le sandbox n'a pas accès à
`/sys/kernel/btf/vmlinux`, et embarquer un vmlinux.h vendoré pour
chaque kernel cible n'est pas viable.

## Module NixOS + flake (workflow GitOps recommandé)

Le repo embarque un `flake.nix` qui expose `nixosModules.default`,
`packages.default`, une bibliothèque composable `lib.policies`, et un
`checks.vm-test` qui boote une VM NixOS et atteste que le datapath
drop bien le flux matché. Le mode de consommation prévu est un flake
de déploiement dans le repo d'infra existant :

```nix
{
  inputs = {
    nixpkgs.url      = "github:NixOS/nixpkgs/nixos-25.11";
    microsegebpf.url = "github:aambert/nixos-microsegebpf";
  };

  outputs = { self, nixpkgs, microsegebpf, ... }: {
    nixosConfigurations.workstation = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        microsegebpf.nixosModules.default
        ({ ... }: {
          services.microsegebpf = {
            enable = true;
            policies = with microsegebpf.lib.policies.baselines; [
              (deny-public-dns {})
              (sshd-restrict { allowFrom = "10.0.0.0/24"; })
              (deny-rfc1918-from-user-session {})
            ];
            hubble.ui.enable = true;
          };
        })
      ];
    };

    # Re-exporte le test VM upstream pour que `nix flake check` du repo
    # d'infra gate les déploiements sur la même assertion bout-en-bout.
    checks = microsegebpf.checks;
  };
}
```

### Workflow GitOps

1. Éditer une policy dans le repo d'infra sous forme d'expression Nix
   (composable, pas de YAML brut).
2. `git push`. La CI lance `nix flake check`. Le `checks.vm-test`
   composé boote une VM NixOS, applique la nouvelle policy, et
   atteste le verdict drop dans le noyau — les policies cassées
   échouent en CI avant qu'aucun hôte ne les voie.
3. La CI déploie via le pipeline existant : `nixos-rebuild switch
   --flake .`, `deploy-rs`, `colmena`, ou `morph`.
4. systemd remarque que le hash de l'`ExecStart` change (le chemin du
   fichier de policy dans `/nix/store` change), redémarre
   `microsegebpf-agent`, et les maps eBPF sont repeuplées en moins
   d'une seconde.
5. Rollback à tout moment via `nixos-rebuild --rollback`. La
   génération de policy précédente est toujours dans le store.

Un flake de déploiement complet vit dans
[`examples/deployment/flake.nix`](examples/deployment/flake.nix).

### Baselines de policies disponibles

`microsegebpf.lib.policies.baselines` fournit out of the box :

| Fonction | Effet |
|---|---|
| `deny-public-dns { cgroupPath, extraIPv4, extraIPv6 }` | Drop les connexions directes vers Cloudflare, Google, Quad9, OpenDNS, AdGuard sur TCP+UDP/53, /443, /853 depuis l'arbre cgroup choisi. Force la résolution via le resolver corporate. |
| `sshd-restrict { allowFrom, port }` | Restreint l'ingress de `sshd.service` à un seul CIDR. |
| `deny-rfc1918-from-user-session { cgroupPath, ports }` | Bloque les mouvements latéraux RFC1918 depuis la session utilisateur. |
| `smtp-relay-only { relayCIDR, port }` | Egress sur TCP/25 uniquement vers le relais nommé ; tout le reste est drop. |
| `deny-threat-feed { ips, cgroupPath, ports }` | Bloque une liste explicite d'IP C2/sinkhole. L'appelant fournit la liste, typiquement générée depuis un feed threat-intel au déploiement. |
| `deny-host { hostnames, ports, protocol, cgroupPath }` | Deny L3/L4 par FQDN. L'agent résout chaque hostname à chaque Apply et installe une entrée /32 (v4) ou /128 (v6) par record A/AAAA. Suit la destination à mesure que ses records DNS rotent — pratique pour les services CDN-hostés où une CIDR statique devient stale. |
| `deny-sni { hostnames }` | Deny TLS peek par SNI. Accepte les patterns exacts (`facebook.com`) et les wildcards à un niveau (`*.facebook.com`). Backé par un trie LPM sur le hostname inversé, voir ARCHITECTURE.fr.md §9.2. |
| `deny-alpn { protocols }` | Deny TLS peek par identifiant ALPN (`h2`, `http/1.1`, `imap`, `smtp`, ...). À utiliser avec parcimonie : bloquer `h2` en blanket flingue presque tout client HTTPS moderne. |

Pour des règles ponctuelles, utiliser `microsegebpf.lib.policies.mkPolicy`,
`drop` et `allow` directement — voir
[`nix/policies/default.nix`](nix/policies/default.nix). `mkPolicy`
accepte aussi `sniDeny` / `alpnDeny` inline pour du matching TLS
ad-hoc sans passer par les baselines.

### Import direct du module (sans flake)

Si tu n'utilises pas les flakes :

```nix
{ ... }: {
  imports = [ /chemin/vers/nixos-microsegebpf/nix/microsegebpf.nix ];

  services.microsegebpf = {
    enable          = true;
    enforce         = false;          # observe-only le temps de valider les policies
    emitAllowEvents = true;           # voir tout le trafic dans Hubble pendant la phase de bake-in
    defaultEgress   = "allow";
    defaultIngress  = "allow";
    resolveInterval = "60s";          # filet de sécurité ; inotify gère le temps réel

    policies = [
      ''
        apiVersion: microseg.local/v1
        kind: Policy
        metadata: { name: deny-public-dns }
        spec:
          selector: { cgroupPath: /user.slice }
          egress:
            - { action: drop, cidr: 1.1.1.0/24, ports: ["443", "853"], protocol: tcp }
            - { action: drop, cidr: 2001:4860::/32, ports: ["443", "853"], protocol: tcp }
      ''
    ];

    hubble.ui.enable = true;          # UI co-localisée sur http://localhost:12000
  };
}
```

Le module embarque un durcissement systemd aligné sur les
recommandations ANSSI poste de travail :
`CapabilityBoundingSet = [ CAP_BPF CAP_NET_ADMIN CAP_PERFMON
CAP_SYS_RESOURCE ]`, `NoNewPrivileges`, `ProtectSystem=strict`,
`SystemCallFilter` restreint à `@system-service @network-io bpf`, et
`ReadWritePaths` limité à `/sys/fs/bpf`. L'agent n'a jamais besoin du
root complet.

## Arborescence du dépôt

```
bpf/microseg.c              Datapath kernel-side (cgroup_skb, LPM trie, IPv4+IPv6, TLS SNI/ALPN)
bpf/microseg_bpfel.{go,o}   Output bpf2go (commité ; régénéré via `make generate`)
bpf/vmlinux.h               Dump BTF pour CO-RE (commité ; régénéré via `make generate`)
pkg/loader/                 Loader basé sur cilium/ebpf : load .o, attache au cgroupv2, lecteur ring buffer
pkg/policy/                 Schéma YAML, résolution des selectors, sync des maps BPF (Apply/Resolve)
pkg/identity/               Walker cgroup (Snapshot) + watcher inotify avec pub/sub Subscribe()
pkg/observer/               Serveur gRPC observer.proto Hubble, conversion vers protobuf flow
cmd/microseg-agent/         Point d'entrée du daemon
cmd/microseg-probe/         Client Hubble CLI pour inspection sans interface
nix/microsegebpf.nix        Module NixOS (services.microsegebpf)
nix/package.nix             Dérivation buildGoModule avec vendorHash et preBuild BPF
nix/policies/               Bibliothèque composable de policies (mkPolicy + 8 baselines : deny-public-dns, sshd-restrict, deny-rfc1918-from-user-session, smtp-relay-only, deny-threat-feed, deny-host, deny-sni, deny-alpn)
nix/tests/vm-test.nix       nixosTest : verdict drop dans le noyau (L3/L4 + FQDN), SNI exact + wildcard (v4 + v6)
flake.nix                   Outputs de flake (packages, nixosModules, lib, checks)
default.nix, shell.nix      Points d'entrée hors flake
.github/workflows/          GitHub Actions : nix-build (rapide), vm-test (lent), security (govulncheck + reuse + SBOM drift + grype hubble-ui, cron nightly)
examples/policy.yaml        Bundle d'exemple de policies en YAML brut
examples/tls-policy.yaml    Exemple de policy TLS-aware (sniDeny/alpnDeny)
examples/fqdn-policy.yaml   Exemple de policy FQDN par hostname (host: example.com)
examples/deployment/        Flake consommateur d'exemple (la cible GitOps)
LICENSES/                   Textes de licence SPDX (MIT, GPL-2.0-only — bpf/microseg.c est dual-licensed pour les helpers GPL-only du sous-système BPF)
REUSE.toml                  Annotations REUSE-spec pour fichiers sans header SPDX inline
ARCHITECTURE.md / .fr.md    Plongée technique sur le datapath eBPF, layout de clé LPM, modèle d'identité, peek TLS, pipeline log-shipping (EN + FR)
SECURITY-AUDIT.md / .fr.md  Audit de sécurité structuré (scoring CVSS 3.1, findings code-review manuelle, matrice reachability par-CVE pour dépendances upstream, roadmap remediation ; EN + FR)
sbom/                       SBOMs CycloneDX 1.5/1.6 + SPDX 2.3 + CSV pour l'arbre source, modules Go, closure runtime agent, et closure Vector (régénérables via la recette dans `sbom/README.md`)
```

## Limites et roadmap

Ce que ce projet **ne fait pas** délibérément :

- **Pas de parsing L7 *de contenu*.** Pas de matching de chemin
  HTTP, pas de filtrage de méthode gRPC, pas de notion de topic
  Kafka, pas d'interception TLS. Le parser TLS est *peek-only* —
  il inspecte les extensions SNI/ALPN en clair et ne déchiffre
  jamais. Ajouter du L7 payload-aware imposerait un sidecar style
  Envoy ; c'est le territoire de Cilium.
- **Pas de réassemblage de fragments.** Le premier fragment porte
  l'en-tête L4 et est filtré ; les suivants ne sont pas classifiés.
  Le trafic poste ne fragmente quasi jamais à ce niveau.
- **Pas de policy DNS-aware pour les hostnames non résolus.**
  « Bloquer `doh.example.com` » fonctionne au moment du TLS via
  `sniDeny` (le SNI est le hostname que le client a tapé). Ça ne
  fonctionne **pas** pour le DNS clair — coupler avec un outil de
  policy DNS si tu as besoin de ce point d'enforcement plus tôt.
- **Pas de matching SAN.** Les Subject Alternative Names vivent dans
  le certificat du serveur (envoyé en ServerHello/Certificate), pas
  dans le ClientHello du client. Notre parser ne voit que les
  métadonnées côté client. Le matching SAN serait utile pour de
  l'*audit* mais pas pour de la *prévention*.
- **TLS 1.3 ECH (Encrypted Client Hello)** est la menace long terme
  au matching SNI. Quand une destination négocie ECH (Cloudflare et
  Firefox déploient ça progressivement depuis 2024), le SNI interne
  est chiffré et on fail-open silencieusement. Horizon 2-3 ans avant
  que ça devienne le défaut.
- **Le scoping TLS par cgroup** n'est pas modélisé : les deny lists
  SNI / ALPN sont globales à l'hôte. Le selector au niveau du
  policy doc est documentaire dans ce cas. Une map keyée
  `(cgroup_id, hash)` est un follow-up raisonnable.

Sur la roadmap :

- Action `audit` qui miroite `LOG` en estampillant le flux avec des
  métadonnées forensiques supplémentaires (chemin du binaire, ligne
  de commande)
- Scoping deny TLS par cgroup (lever le caveat documentaire-seul
  ci-dessus)
- Extraction SNI HTTP/3 / QUIC dès qu'un helper AES in-kernel ou un
  chemin userspace-roundtrip viable arrive

## Licence

Tous les fichiers source sont sous Licence MIT. Le programme eBPF
kernel-side dans `bpf/microseg.c` est en plus annoté GPL-2.0-only
via une expression SPDX duale et déclare la chaîne LICENSE runtime
`"Dual MIT/GPL"` pour que le sous-système BPF l'accepte avec les
helpers GPL-only (`bpf_loop`, `bpf_skb_cgroup_id`, etc).

<!-- REUSE-IgnoreStart -->
Le header SPDX exact sur `bpf/microseg.c` est
`SPDX-License-Identifier: (MIT AND GPL-2.0-only)`. L'outil
`reuse lint` essaierait sinon de parser la phrase markdown qui
l'enveloppe comme une vraie déclaration de licence ; les
commentaires IgnoreStart/End lui disent de sauter ce paragraphe.
<!-- REUSE-IgnoreEnd -->

Conforme REUSE : chaque fichier a soit un header SPDX inline soit
un glob dans [`REUSE.toml`](REUSE.toml). Vérifier avec
`reuse lint`. Voir [LICENSE](LICENSE) pour la décomposition par
fichier et [`LICENSES/MIT.txt`](LICENSES/MIT.txt) pour le texte
canonique ; [`LICENSES/GPL-2.0-only.txt`](LICENSES/GPL-2.0-only.txt)
porte le texte de la licence duale exigée par le sous-système BPF.

## Remerciements

Ce projet n'existerait pas sans le travail upstream de :

- [Cilium](https://cilium.io/) et la bibliothèque Go
  [`cilium/ebpf`](https://github.com/cilium/ebpf)
- [Hubble](https://github.com/cilium/hubble) et son `observer.proto`
- [Tetragon](https://github.com/cilium/tetragon) — pour avoir prouvé
  qu'une infra eBPF de type Cilium a du sens hors Kubernetes, même si
  Tetragon lui-même résout un problème différent
