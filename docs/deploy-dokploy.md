# Déployer les relais dans Dokploy

Deux applications Dokploy, une par image, et un fichier de configuration dynamique pour
Traefik. Rien n'est propre au déploiement dans le code : tout passe par les variables
ci-dessous.

Le domaine du service n'est pas encore choisi (**[à trancher]**). Ce guide écrit :

| Nom | Exemple | Rôle |
|---|---|---|
| `ZONE_MAISONS` | `maisons.exemple.fr` | zone des maisons ; enregistrement `*.ZONE_MAISONS` vers le VPS |
| `relais.DOMAINE` | `relais.exemple.fr` | entrée des tunnels des maisons |
| `push.DOMAINE` | `push.exemple.fr` | relais push |

## Ce qui a été vérifié

- **Version de Traefik** : Dokploy v0.30.10 (octobre 2026) lance `traefik:v3.7.16`
  (constante `TRAEFIK_VERSION` de `packages/server/src/setup/traefik-setup.ts`, modifiable
  par la variable `TRAEFIK_VERSION` de Dokploy). Le point d'entrée HTTPS s'appelle
  `websecure` (`:443`), le résolveur de certificats `letsencrypt` (défi HTTP-01 sur `web`,
  `:80`). La configuration dynamique est lue dans `/etc/dokploy/traefik/dynamic/`
  (surveillée : pas de redémarrage nécessaire).
- **`HostSNIRegexp`** : en v3, c'est une expression régulière Go
  (``HostSNIRegexp(`^[a-z2-7]{16}\.maisons\.exemple\.fr$`)``), sans les gabarits `{nom}` de
  la v2. `HostSNI` accepte aussi un joker d'un niveau (``HostSNI(`*.maisons.exemple.fr`)``).
  On garde l'expression stricte : Traefik écarte déjà tout nom qui ne peut pas être une
  maison (16 caractères base32).
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

| Enregistrement | Vers |
|---|---|
| `*.ZONE_MAISONS` (A, AAAA) | IP du VPS |
| `relais.DOMAINE` (A, AAAA) | IP du VPS |
| `push.DOMAINE` (A, AAAA) | IP du VPS |

Le port 80 doit rester ouvert : Let's Encrypt valide `relais.DOMAINE` et `push.DOMAINE` en
HTTP-01. Les certificats des maisons ne passent pas par Traefik : chaque maison obtient le sien
en DNS-01, par le plan de contrôle, et sa clé reste chez elle.

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
- **Réplicas : 1, impérativement.** Une maison est connectée à une seule instance. Avec deux
  réplicas derrière le même Traefik, un client pourrait arriver sur l'instance qui ne la
  connaît pas. Plusieurs relais, ce sont plusieurs VPS annoncés aux maisons par le plan de
  contrôle, pas des réplicas.
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
| `RELAY_SNI_ZONE` | `maisons.exemple.fr` | `ZONE_MAISONS` |
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
- **Domaine** (interface Dokploy) : `push.DOMAINE`, port du conteneur `8080`, HTTPS,
  certificat `letsencrypt`. C'est un routeur HTTP ordinaire.
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
(APNs ou FCM indisponible), `503` (relais surchargé).

## Configuration dynamique de Traefik

Fichier `/etc/dokploy/traefik/dynamic/agendo-relais.yml` (*Traefik → File System* dans
Dokploy, ou sur l'hôte). Remplacer les domaines et le nom du service (`appName` de
l'application `relay-sni`). Les expressions sont entre apostrophes YAML : les `\` n'ont pas à
être doublés.

```yaml
tcp:
  routers:
    # Navigateurs et app vers une maison : TLS jamais déchiffré.
    agendo-maisons:
      entryPoints: [websecure]
      rule: 'HostSNIRegexp(`^[a-z2-7]{16}\.maisons\.exemple\.fr$`)'
      tls:
        passthrough: true
      service: agendo-relay-sni-public
    # Tunnels des maisons : TLS terminé par Traefik.
    agendo-tunnels:
      entryPoints: [websecure]
      rule: 'HostSNI(`relais.exemple.fr`)'
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
# Le certificat de relais.DOMAINE est servi par Traefik.
openssl s_client -connect relais.exemple.fr:443 -servername relais.exemple.fr </dev/null | head -5
# Un nom de maison inconnu : connexion fermée par le relais, sans réponse TLS.
openssl s_client -connect abcdefghijklmnop.maisons.exemple.fr:443 -servername abcdefghijklmnop.maisons.exemple.fr </dev/null
# Relais push : refus explicite sans jeton.
curl -s -X POST https://push.exemple.fr/v1/push   # {"status":"rejected","detail":"jeton push absent"}
```

Dans les logs du relais SNI (`relais SNI à l'écoute`, puis `tunnel ouvert` pour chaque maison),
une ligne `connexion publique d'un pair non autorisé` signale un `RELAY_SNI_PROXY_FROM` qui ne
couvre pas l'adresse de Traefik.

## Métriques

Port interne `9100`, jamais routé par Traefik : `GET /metrics` (texte Prometheus) et
`GET /sante` (`ok`). Séries : `relay_sni_tunnels`, `relay_sni_streams`,
`relay_sni_handshakes_total{result}`, `relay_sni_public_connections_total{result}`,
`relay_sni_bytes_total{direction}`, `relay_push_requests_total{status}`,
`relay_push_upstream_errors_total{platform}`. Aucune étiquette ne porte de nom d'hôte ni d'IP.

L'image `scratch` n'a pas de shell : pas de `HEALTHCHECK` Docker. La politique de redémarrage
de Dokploy relance un relais arrêté.

## Sauvegardes

Rien à sauvegarder : les relais n'ont ni base ni état. Les deux secrets du relais push (clé
`.p8`, compte de service FCM) se gardent hors du VPS, par exemple dans le gestionnaire de mots
de passe, pour pouvoir les remonter.

## Mode autonome

Pour un relais sur un VPS sans Traefik : `RELAY_SNI_PROXY_PROTOCOL=off`, port public publié
sur `443`. La terminaison TLS de `relais.DOMAINE` sur le port des tunnels n'est **pas**
implémentée en V1 (prévu par la spec, non requis) : il faut encore un proxy TLS devant
`9443`.

## Dépendance vers le socle (CI)

Le protocole commun vient du crate `agendo-access-protocol` du dépôt `charlyhue/agendo`,
privé. En développement, `Cargo.toml` pointe sur le dépôt local
(`file:///Users/chue/workspace/agendo`, branche `agendo-access`). En CI,
`scripts/ci-agendo-github.sh` réécrit cette URL en `ssh://git@github.com/charlyhue/agendo.git`,
au même commit que les `Cargo.lock`. Cargo passe alors par `git` et l'agent SSH
(`CARGO_NET_GIT_FETCH_WITH_CLI=true`).

Mise en place, une fois :

1. **Pousser la branche `agendo-access` du socle sur GitHub.** Elle n'existe aujourd'hui qu'en
   local, et sans elle la CI ne trouve pas le commit figé dans `Cargo.lock`.
2. Créer une paire de clés dédiée, sans phrase de passe (elle ne sert qu'à cela) :
   `ssh-keygen -t ed25519 -N "" -C "ci agendo-access-relays" -f agendo-deploy`.
3. Dans `charlyhue/agendo`, **Settings → Deploy keys → Add deploy key** : contenu de
   `agendo-deploy.pub`, **sans** l'accès en écriture.
4. Dans `charlyhue/agendo-access-relays`, **Settings → Secrets and variables → Actions** :
   secret `AGENDO_DEPLOY_KEY` = contenu de `agendo-deploy` (la clé privée).
5. Supprimer les deux fichiers locaux.
6. Même endroit : `DOKPLOY_WEBHOOK_RELAY_SNI` et `DOKPLOY_WEBHOOK_RELAY_PUSH`, URL du webhook
   de chaque application (*Deployments → Webhook URL*, déploiement automatique activé). Sans
   eux, la CI pousse les images et saute le déploiement.

Plus tard, quand le protocole aura une étiquette sur GitHub, remplacer dans `Cargo.toml` (et
`fuzz/Cargo.toml`) la dépendance par
`git = "ssh://git@github.com/charlyhue/agendo.git", tag = "…"`, puis supprimer le script de
réécriture. Le jour où le socle devient public, l'URL `https://` suffit et la clé de
déploiement peut être révoquée.

L'image Docker se construit **hors ligne**, sur les sources vendues par `scripts/vendor.sh`
(étape de la CI juste avant le build) : aucune clé n'entre dans l'image ni dans le contexte
de build.
