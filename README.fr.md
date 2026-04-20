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

Six exemples concrets couvrant les formes les plus courantes de
durcissement poste. Chacun est un fragment complet de
`services.microsegebpf.policies` qu'on peut déposer dans son flake
de déploiement.

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
nix/policies/               Bibliothèque composable de policies (mkPolicy + 7 baselines)
nix/tests/vm-test.nix       nixosTest exerçant le verdict drop dans le noyau + wildcards SNI
flake.nix                   Outputs de flake (packages, nixosModules, lib, checks)
default.nix, shell.nix      Points d'entrée hors flake
.github/workflows/          GitHub Actions : nix-build (rapide), vm-test (lent)
examples/policy.yaml        Bundle d'exemple de policies en YAML brut
examples/tls-policy.yaml    Exemple de policy TLS-aware (sniDeny/alpnDeny)
examples/deployment/        Flake consommateur d'exemple (la cible GitOps)
LICENSES/                   Textes de licence SPDX (MIT, CC-BY-SA-4.0)
REUSE.toml                  Annotations REUSE-spec pour fichiers sans header SPDX inline
ARCHITECTURE.md             Plongée technique sur le datapath eBPF, layout de clé LPM, modèle d'identité
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
- **Le flush de map à l'Apply** est un sweep complet, pas un delta.
  Acceptable à l'échelle d'un poste (quelques milliers d'entrées)
  mais pas pour un équipement classe routeur.
- **Le scoping TLS par cgroup** n'est pas modélisé : les deny lists
  SNI / ALPN sont globales à l'hôte. Le selector au niveau du
  policy doc est documentaire dans ce cas. Une map keyée
  `(cgroup_id, hash)` est un follow-up raisonnable.

Sur la roadmap :

- Mises à jour de map en delta plutôt que flush-and-fill
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
via `SPDX-License-Identifier: (MIT AND GPL-2.0-only)` et déclare
la chaîne LICENSE runtime `"Dual MIT/GPL"` pour que le sous-système
BPF l'accepte avec les helpers GPL-only (`bpf_loop`,
`bpf_skb_cgroup_id`, etc).

Conforme REUSE : chaque fichier a soit un header SPDX inline soit
un glob dans [`REUSE.toml`](REUSE.toml). Vérifier avec
`reuse lint`. Voir [LICENSE](LICENSE) pour la décomposition par
fichier et [`LICENSES/MIT.txt`](LICENSES/MIT.txt) pour le texte
canonique.

## Remerciements

Ce projet n'existerait pas sans le travail upstream de :

- [Cilium](https://cilium.io/) et la bibliothèque Go
  [`cilium/ebpf`](https://github.com/cilium/ebpf)
- [Hubble](https://github.com/cilium/hubble) et son `observer.proto`
- [Tetragon](https://github.com/cilium/tetragon) — pour avoir prouvé
  qu'une infra eBPF de type Cilium a du sens hors Kubernetes, même si
  Tetragon lui-même résout un problème différent
