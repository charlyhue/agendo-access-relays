# Déployer les relais dans Dokploy

Deux applications Dokploy, une par image, et un fichier de configuration dynamique pour
Traefik. Rien n'est propre au déploiement dans le code : tout passe par les variables
ci-dessous.

Les domaines sont choisis, **temporairement** (trois maisons tenues par la personne) ; ils
changeront. Le code n'en contient aucun : ils n'apparaissent que dans les variables
d'environnement, la configuration de Traefik et le DNS. Changer de domaine, c'est changer ces
trois endroits (et la configuration du plan de contrôle), sans nouvelle image.

| Rôle | Nom | Remarque |
|---|---|---|
| zone des maisons (`ZONE_MAISONS`) | `<id>.home.agendo.charly-hue.fr` | joker `*.home.agendo.charly-hue.fr` : une adresse A/AAAA **par relais** |
| tunnels des maisons, un nom par instance | `relay-1.agendo.charly-hue.fr`, `relay-2.agendo.charly-hue.fr`… | TLS terminé par Traefik, puis `relay-sni:9443` |
| relais push, un nom par instance | `push-1.agendo.charly-hue.fr`, `push-2.agendo.charly-hue.fr`… | HTTP derrière Traefik, puis `relay-push:8080` |

En V1, seules les instances `-1` existent. Les noms des tunnels et du push ne sont jamais
partagés entre plusieurs IP : Traefik obtient leurs certificats par le défi HTTP-01, et
Let's Encrypt pourrait poser la question au mauvais serveur, qui n'a pas le jeton du défi.
Le joker des maisons, lui, peut pointer sur plusieurs serveurs, puisque Traefik n'en délivre
aucun certificat (passthrough).

Avec ce domaine temporaire, les maisons partagent le domaine enregistré `charly-hue.fr` avec
les autres sites de la personne. Deux conséquences : la limite de Let's Encrypt (50
certificats par semaine pour `charly-hue.fr`) est commune, sans gêne pour trois maisons ; et
l'inscription à la Public Suffix List, qui isolerait les cookies des maisons, n'a pas de sens
sur un domaine provisoire. Elle reste à faire sur le domaine définitif.

## Ce qui a été vérifié

- **Version de Traefik** : Dokploy v0.30.10 (octobre 2026) lance `traefik:v3.7.16`
  (constante `TRAEFIK_VERSION` de `packages/server/src/setup/traefik-setup.ts`, modifiable
  par la variable `TRAEFIK_VERSION` de Dokploy). Le point d'entrée HTTPS s'appelle
  `websecure` (`:443`), le résolveur de certificats `letsencrypt` (défi HTTP-01 sur `web`,
  `:80`). La configuration dynamique est lue dans `/etc/dokploy/traefik/dynamic/`
  (surveillée : pas de redémarrage nécessaire).
- **`HostSNIRegexp`** : en v3, c'est une expression régulière Go
  (``HostSNIRegexp(`^[a-z0-9]+\.home\.agendo\.charly-hue\.fr$`)``), sans les gabarits `{nom}` de
  la v2. `HostSNI` accepte aussi un joker d'un niveau (``HostSNI(`*.home.agendo.charly-hue.fr`)``).
  L'expression n'admet qu'une étiquette de minuscules et de chiffres devant la zone ; le
  relais refuse ensuite tout nom qu'aucune maison connectée ne sert.
- **`proxyProtocol`** : depuis Traefik v3.5.2, il se règle dans un
  `tcp.serversTransports.<nom>` que le service désigne par `serversTransport`. L'ancienne
  forme, `loadBalancer.proxyProtocol`, est dépréciée.
- **Délais d'inactivité** : `respondingTimeouts.readTimeout` (60 s par défaut en v3) ne coupe
  pas les connexions TCP. Pour un routeur TCP, Traefik lève le délai dès le ClientHello lu
  (`pkg/server/router/tcp/router.go` : *Remove read/write deadline and delegate this to
  underlying TCP server*). Le proxy TCP n'a pas de délai d'inactivité : seul
  `terminationDelay` (100 ms) s'applique après une demi-fermeture (`pkg/tcp/proxy.go`). Un
  tunnel de plusieurs jours tient donc. Le relais envoie de toute façon un `PING` toutes les
  25 s. Un redémarrage de Traefik (mise à jour de Dokploy) coupe les tunnels, et les maisons
  se reconnectent.

## DNS

V1, un seul serveur (IP `IP1`) :

| Enregistrement | Type | Valeur | TTL |
|---|---|---|---|
| `*.home.agendo.charly-hue.fr` | A (et AAAA si le VPS a de l'IPv6) | `IP1` | **60 s** |
| `relay-1.agendo.charly-hue.fr` | A, AAAA | `IP1` | défaut |
| `push-1.agendo.charly-hue.fr` | A, AAAA | `IP1` | défaut |

Le port 80 doit rester ouvert : Let's Encrypt valide `relay-1.agendo` et `push-1.agendo` en
HTTP-01. Les certificats des maisons ne passent pas par Traefik : chaque maison obtient le sien
en DNS-01 (`_acme-challenge.<id>.home.agendo.charly-hue.fr`, posé par le plan de contrôle), et sa
clé reste chez elle. Le fournisseur DNS de `charly-hue.fr` doit donc être celui que pilote le
plan de contrôle.

### Plusieurs relais : une adresse par relais dans le joker

Chaque maison ouvre un tunnel vers **chacun** des relais que lui annonce le plan de contrôle
(`relays: ["tls://relay-1.agendo.charly-hue.fr", "tls://relay-2.agendo.charly-hue.fr"]`).
Toutes les maisons sont donc joignables par tous les relais, et le joker
`*.home.agendo.charly-hue.fr` porte une adresse A/AAAA par relais : un navigateur qui arrive sur
n'importe laquelle trouve la maison.

### Panne d'un relais : retirer son IP

1. Retirer l'adresse du serveur en panne (A et AAAA) de `*.home.agendo.charly-hue.fr`. Ne pas
   toucher à `relay-N.agendo` ni à `push-N.agendo`.
2. Avec un TTL de 60 s, les résolveurs oublient l'adresse en une minute environ. Certains
   navigateurs et résolveurs gardent une réponse un peu plus longtemps : prévoir quelques
   minutes. Un navigateur qui a reçu les deux adresses essaie souvent l'autre de lui-même
   quand la connexion échoue.
3. Les maisons n'ont rien à faire : leur tunnel vers le relais en panne se reconnecte en boucle
   (recul exponentiel), celui vers l'autre relais continue.
4. Au retour du serveur, vérifier que des tunnels y sont rouverts (log `tunnel ouvert`, métrique
   `relay_sni_tunnels`), **puis seulement** remettre son adresse dans le joker.

Le TTL de 60 s ne concerne que le joker : c'est le seul enregistrement qu'on modifie en cas de
panne.

## Images

`ghcr.io/charlyhue/agendo-relay-sni` et `ghcr.io/charlyhue/agendo-relay-push`, poussées par la
CI à chaque commit sur `main`, avec deux étiquettes :

- `:<sha du commit>`, immuable : traçabilité et retour arrière ;
- `:main`, déplacée à chaque build : c'est celle que suivent les applications Dokploy.

Tant que les images sont privées, déclarer le registre dans Dokploy (**Settings → Registry**) :
`ghcr.io`, utilisateur GitHub, jeton personnel limité à `read:packages`.

**Retour arrière** : dans l'application, remplacer `:main` par `:<sha>` puis **Deploy**.

## Application `relay-sni`

- **Source** : Docker, image `ghcr.io/charlyhue/agendo-relay-sni:main`.
- **Réplicas : 1, impérativement.** Le tunnel d'une maison arrive sur une seule instance. Avec
  deux réplicas derrière le même Traefik, un client pourrait arriver sur l'instance qui ne la
  connaît pas. Plusieurs relais, ce sont plusieurs serveurs, chacun avec son nom
  `relay-N.agendo` annoncé aux maisons par le plan de contrôle (voir « Deuxième serveur »),
  pas des réplicas.
- **Domaines** : aucun dans l'interface. Le routage TCP passe par le fichier dynamique
  ci-dessous.
- **Ports** : aucun port publié. Traefik joint le conteneur par le réseau `dokploy-network`.
- **Montages** : aucun. Le relais SNI n'a **aucun secret**.
- **Arrêt** : sur SIGTERM, `GOAWAY` 0 à toutes les maisons, puis 5 s de grâce. Le délai
  d'arrêt de Docker (10 s par défaut) suffit.
- **Nom de l'application** (`appName`) : Dokploy y ajoute un suffixe aléatoire
  (`agendo-relay-sni-a1b2c3`). C'est le nom DNS du service sur `dokploy-network`, à reporter
  dans la configuration de Traefik.

Variables d'environnement :

| Variable | Valeur | Remarque |
|---|---|---|
| `RELAY_SNI_ZONE` | `home.agendo.charly-hue.fr` | `ZONE_MAISONS` : seuls les jetons d'un hôte de cette zone sont admis |
| `RELAY_TRUSTED_KEYS` | `k1=<clé publique>` | clés publiques du plan de contrôle (`GET /.well-known/agendo-access/keys`), plusieurs pour une rotation : `k1=…,k2=…` |
| `RELAY_SNI_PROXY_FROM` | sous-réseau de `dokploy-network` | `docker network inspect dokploy-network -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}'`. Seul Traefik doit pouvoir envoyer l'en-tête PROXY. |
| `RELAY_METRICS_ADDR` | `0.0.0.0:9100` | si un collecteur lit les métriques depuis le réseau Docker ; défaut `127.0.0.1:9100` |
| `RELAY_LOG` | `info` | filtre des logs (`debug` pour suivre les refus) |

Seuils (valeurs par défaut, à ajuster seulement au besoin) :

| Variable | Défaut |
|---|---|
| `RELAY_SNI_PUBLIC_ADDR` / `RELAY_SNI_TUNNEL_ADDR` | `0.0.0.0:8443` / `0.0.0.0:9443` |
| `RELAY_SNI_PROXY_PROTOCOL` | `on` (`off` : mode autonome, voir plus bas) |
| `RELAY_SNI_MAX_CONNECTIONS` / `_PER_IP` | `4096` / `64` |
| `RELAY_SNI_MAX_TUNNELS` / `_PER_IP` | `4096` / `8` |
| `RELAY_SNI_MAX_STREAMS_PER_TUNNEL` | `1024` |
| `RELAY_SNI_INITIAL_WINDOW` | `262144` (octets, de 16 Kio à 16 Mio) |
| `RELAY_SNI_HELLO_TIMEOUT_SECS` / `_HANDSHAKE_TIMEOUT_SECS` | `10` / `10` |
| `RELAY_SNI_PING_INTERVAL_SECS` | `25` |
| `RELAY_SNI_WRITE_TIMEOUT_SECS` / `_IDLE_TIMEOUT_SECS` | `30` / `3600` |
| `RELAY_SNI_SHUTDOWN_GRACE_SECS` | `5` |

La mémoire tenue par le relais est bornée par flux à la fenêtre (256 Kio par sens par
défaut). Le pire cas vaut à peu près `RELAY_SNI_MAX_CONNECTIONS × 2 × fenêtre`.

## Application `relay-push`

- **Source** : Docker, image `ghcr.io/charlyhue/agendo-relay-push:main`.
- **Domaine** (interface Dokploy) : `push-1.agendo.charly-hue.fr`, chemin `/`, port du
  conteneur `8080`, HTTPS, certificat `letsencrypt`. C'est un routeur HTTP ordinaire. Le plan
  de contrôle l'annonce aux maisons par son URL de base
  (`push_urls: ["https://push-1.agendo.charly-hue.fr"]`).
- **Réplicas** : 1 suffit. Avec plusieurs, les quotas (en mémoire, par instance) deviennent
  plus larges d'autant.
- **Montages** (*Advanced → Mounts → File Mount*), contenus collés dans Dokploy, jamais dans
  Git :
  - `/secrets/apns.p8` : clé d'authentification APNs (console Apple Developer, *Keys*) ;
  - `/secrets/fcm.json` : compte de service Firebase (*Project settings → Service accounts*),
    si Android est servi.

  Le conteneur tourne sous l'utilisateur 65534. Le fichier monté doit lui être lisible.
  Dokploy écrit les montages de fichiers sur l'hôte : leur accès sur l'hôte doit rester
  réservé à root.

Variables d'environnement :

| Variable | Valeur |
|---|---|
| `RELAY_TRUSTED_KEYS` | `k1=<clé publique>` (comme pour le relais SNI) |
| `RELAY_PUSH_APNS_KEY_FILE` | `/secrets/apns.p8` |
| `RELAY_PUSH_APNS_KEY_ID` | identifiant de la clé (10 caractères) |
| `RELAY_PUSH_APNS_TEAM_ID` | équipe Apple (`YKK2T3KYX3`) |
| `RELAY_PUSH_APNS_TOPIC` | identifiant de l'app iOS |
| `RELAY_PUSH_APNS_ENV` | `production` (app TestFlight ou App Store) ou `sandbox` (app de développement) |
| `RELAY_PUSH_FCM_SERVICE_ACCOUNT_FILE` | `/secrets/fcm.json` (seulement si Android) |
| `RELAY_METRICS_ADDR` | `0.0.0.0:9100` pour une collecte ; défaut `127.0.0.1:9100` |

Seuils : `RELAY_PUSH_MAX_BODY` (`8192` octets), `RELAY_PUSH_TIMEOUT_SECS` (`10`),
`RELAY_PUSH_MAX_CONCURRENT` (`256`), `RELAY_PUSH_MAX_HOUSES` (`100000`). Les quotas de chaque
maison viennent de son jeton push, pas de la configuration.

Codes rendus par `POST /v1/push` : `200` (`sent`, `unregistered`), `400`/`401`/`413`
(`rejected` par le relais), `422` (`rejected` par APNs ou FCM), `429` (`quota`), `502`
(`unavailable` : APNs ou FCM en panne passagère, 5xx, 429 ou délai dépassé), `503`
(`unavailable` : relais surchargé). Seul `unavailable` vaut un nouvel essai, plus tard ou
auprès d'un autre `push-N.agendo` ; `rejected` et `quota` sont définitifs.

L'en-tête `Agendo-Signature` nomme la maison (`house=<id>,t=…,sig=…`) : elle doit être celle
du jeton push (`sub`), sinon `401`.

## Configuration dynamique de Traefik

Fichier `/etc/dokploy/traefik/dynamic/agendo-relais.yml` du serveur 1 (*Traefik → File
System* dans Dokploy, ou sur l'hôte). Reporter le nom du service (`appName` de l'application
`relay-sni`, ici `agendo-relay-sni-a1b2c3`). Les expressions sont entre apostrophes YAML :
les `\` n'ont pas à être doublés.

```yaml
tcp:
  routers:
    # Navigateurs et app vers une maison : TLS jamais déchiffré.
    agendo-maisons:
      entryPoints: [websecure]
      rule: 'HostSNIRegexp(`^[a-z0-9]+\.home\.agendo\.charly-hue\.fr$`)'
      tls:
        passthrough: true
      service: agendo-relay-sni-public
    # Tunnels des maisons : TLS terminé par Traefik. Nom propre à ce serveur (-1, -2…).
    agendo-tunnels:
      entryPoints: [websecure]
      rule: 'HostSNI(`relay-1.agendo.charly-hue.fr`)'
      tls:
        certResolver: letsencrypt
      service: agendo-relay-sni-tunnels

  serversTransports:
    # En-tête PROXY v2 vers le relais : l'adresse réelle du client (ou de la maison).
    agendo-proxy-v2:
      proxyProtocol:
        version: 2

  services:
    agendo-relay-sni-public:
      loadBalancer:
        serversTransport: agendo-proxy-v2
        servers:
          - address: "agendo-relay-sni-a1b2c3:8443"
    agendo-relay-sni-tunnels:
      loadBalancer:
        serversTransport: agendo-proxy-v2
        servers:
          - address: "agendo-relay-sni-a1b2c3:9443"
```

Le port des tunnels reçoit lui aussi l'en-tête PROXY *(choix de conception)* : sans lui, le
relais ne verrait que l'IP de Traefik, et la limite de tunnels par IP ne limiterait rien.

Vérifications après déploiement :

```sh
# Le certificat de relay-1.agendo est servi par Traefik.
openssl s_client -connect relay-1.agendo.charly-hue.fr:443 -servername relay-1.agendo.charly-hue.fr </dev/null | head -5
# Un nom de maison inconnu : connexion fermée par le relais, sans réponse TLS.
openssl s_client -connect inconnue.home.agendo.charly-hue.fr:443 -servername inconnue.home.agendo.charly-hue.fr </dev/null
# Relais push : refus explicite sans jeton.
curl -s -X POST https://push-1.agendo.charly-hue.fr/v1/push   # {"status":"rejected","detail":"jeton push absent"}
```

Dans les logs du relais SNI (`relais SNI à l'écoute`, puis `tunnel ouvert` pour chaque maison),
une ligne `connexion publique d'un pair non autorisé` signale un `RELAY_SNI_PROXY_FROM` qui ne
couvre pas l'adresse de Traefik.

## Deuxième serveur

Un relais de plus, c'est un deuxième VPS piloté par la même instance de Dokploy (**serveur
distant**), avec les mêmes applications et la même configuration. Seuls changent les noms
`-2`, l'IP et le sous-réseau Docker.

1. **Serveur distant** : dans Dokploy, *Remote Servers → Create Server* (IP, utilisateur, clé
   SSH), puis **Setup Server**. Dokploy y installe Docker, le réseau `dokploy-network` et son
   propre Traefik (même version, même entrée `websecure`, même résolveur `letsencrypt`).
2. **DNS**, dans cet ordre :
   - `relay-2.agendo.charly-hue.fr` et `push-2.agendo.charly-hue.fr` (A/AAAA) vers `IP2` ;
   - **pas encore** `IP2` dans le joker `*.home.agendo.charly-hue.fr`.
3. **Applications** : créer `relay-sni` et `relay-push` en choisissant le serveur 2 à la
   création, avec la même image, les mêmes variables et les mêmes montages (clé `.p8`, compte
   FCM). Seule différence : `RELAY_SNI_PROXY_FROM` prend le sous-réseau de `dokploy-network`
   **du serveur 2** (même commande `docker network inspect`, lancée sur ce serveur). Domaine
   du push : `push-2.agendo.charly-hue.fr`.
4. **Traefik du serveur 2** : le même fichier `agendo-relais.yml`, avec
   ``HostSNI(`relay-2.agendo.charly-hue.fr`)`` pour les tunnels et l'`appName` des
   applications du serveur 2. Le routeur des maisons ne change pas.
5. **Plan de contrôle** : ajouter `tls://relay-2.agendo.charly-hue.fr` à la liste des relais et
   `https://push-2.agendo.charly-hue.fr` à celle des relais push. Les maisons la reçoivent au
   renouvellement suivant de leurs jetons (6 h au plus) et ouvrent un second tunnel.
6. **Vérifier** sur le serveur 2 que les tunnels arrivent (`relay_sni_tunnels` égal au nombre
   de maisons rattachées), **puis** ajouter `IP2` au joker `*.home.agendo.charly-hue.fr`. Avant
   cela, un navigateur envoyé vers `IP2` n'y trouverait aucune maison.
7. **CI** : ajouter l'URL du webhook de chaque nouvelle application, sur une nouvelle ligne,
   dans le secret existant (`DOKPLOY_WEBHOOK_RELAY_SNI`, `DOKPLOY_WEBHOOK_RELAY_PUSH`). La CI
   appelle chaque ligne.

Les quotas du relais push sont tenus par instance : avec deux relais push, une maison peut
envoyer jusqu'à deux fois son quota si elle répartit ses envois.

## Métriques

Port interne `9100`, jamais routé par Traefik : `GET /metrics` (texte Prometheus) et
`GET /sante` (`ok`). Séries : `relay_sni_tunnels`, `relay_sni_streams`,
`relay_sni_handshakes_total{result}`, `relay_sni_public_connections_total{result}`,
`relay_sni_bytes_total{direction}`, `relay_sni_renewals_total{result}` (`RENEW` acceptés ou
refusés), `relay_push_requests_total{status}` (dont `unavailable`),
`relay_push_upstream_errors_total{platform}`. Aucune étiquette ne porte de nom d'hôte ni d'IP.

L'image `scratch` n'a pas de shell : pas de `HEALTHCHECK` Docker. La politique de redémarrage
de Dokploy relance un relais arrêté.

## Sauvegardes

Rien à sauvegarder : les relais n'ont ni base ni état. Les deux secrets du relais push (clé
`.p8`, compte de service FCM) se gardent hors du VPS, par exemple dans le gestionnaire de mots
de passe, pour pouvoir les remonter.

## Mode autonome

Pour un relais sur un VPS sans Traefik : `RELAY_SNI_PROXY_PROTOCOL=off`, port public publié
sur `443`. La terminaison TLS de `relay-N.agendo` sur le port des tunnels n'est **pas**
implémentée en V1 (prévu par la spec, non requis) : il faut encore un proxy TLS devant
`9443`.

## Dépendance vers le socle

Le protocole commun vient du crate `agendo-access-protocol` du dépôt `charlyhue/agendo`
(privé), **à un tag** :

```toml
agendo-access-protocol = { git = "ssh://git@github.com/charlyhue/agendo.git", tag = "v0.42.0", features = ["codec"] }
```

(même ligne dans `fuzz/Cargo.toml`, sans `codec`). Le commit exact est figé dans `Cargo.lock`
et `fuzz/Cargo.lock`. `.cargo/config.toml` fait passer Cargo par la CLI git
(`net.git-fetch-with-cli`), qui utilise l'agent SSH : en local la clé personnelle (accès au
dépôt du socle), en CI la clé de déploiement chargée par `webfactory/ssh-agent`
(`CARGO_NET_GIT_FETCH_WITH_CLI=true` y est aussi posé).

**Monter de version** : changer le tag dans `Cargo.toml` et `fuzz/Cargo.toml`, puis
`cargo update -p agendo-access-protocol` à la racine **et** dans `fuzz/`, puis la suite
complète, clippy, `cargo deny check`, `cargo audit` (les deux lockfiles) et le fuzzing.

Mise en place de la CI, une fois :

1. Créer une paire de clés dédiée, sans phrase de passe (elle ne sert qu'à cela) :
   `ssh-keygen -t ed25519 -N "" -C "ci agendo-access-relays" -f agendo-deploy`.
2. Dans `charlyhue/agendo`, **Settings → Deploy keys → Add deploy key** : contenu de
   `agendo-deploy.pub`, **sans** l'accès en écriture.
3. Dans `charlyhue/agendo-access-relays`, **Settings → Secrets and variables → Actions** :
   secret `AGENDO_DEPLOY_KEY` = contenu de `agendo-deploy` (la clé privée).
4. Supprimer les deux fichiers locaux.
5. Même endroit : `DOKPLOY_WEBHOOK_RELAY_SNI` et `DOKPLOY_WEBHOOK_RELAY_PUSH`, URL du webhook
   de chaque application (*Deployments → Webhook URL*, déploiement automatique activé). Avec
   plusieurs serveurs, une URL par ligne. Sans ces secrets, la CI pousse les images et saute
   le déploiement.

Le jour où le socle devient public, l'URL `https://github.com/charlyhue/agendo.git` suffit (plus
de clé ni de CLI git), et la clé de déploiement peut être révoquée.

L'image Docker se construit **hors ligne**, sur les sources vendues par `scripts/vendor.sh`
(étape de la CI juste avant le build, avec l'agent SSH) : aucune clé n'entre dans l'image ni
dans le contexte de build.
