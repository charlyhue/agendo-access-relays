# Agendo Access : relais

Les deux relais du service **Agendo Access** (accès distant et notifications des maisons
Agendo) :

- **`relay-sni`** reçoit les connexions TLS des navigateurs et de l'app vers
  `https://<maison>.<ZONE_MAISONS>` et les passe, **sans les déchiffrer**, à la maison qui sert
  ce nom par le tunnel qu'elle a ouvert. Le relais ne détient aucun secret et n'ouvre aucune
  connexion sortante.
- **`relay-push`** reçoit les notifications des maisons, **chiffrées de bout en bout** entre la
  maison et le téléphone, et les remet à APNs (iOS) ou FCM (Android).

Les relais ne gardent rien, sans base ni état durable : on peut les redémarrer, les maisons se
reconnectent. Ils vérifient les jetons du plan de contrôle avec sa seule clé publique.

Le protocole commun (trames du tunnel, jetons, signatures, format des notifications) vit dans
le crate `agendo-access-protocol` du socle Agendo, dont ce dépôt dépend à un tag (dépôt GitHub
privé pour l'instant : il faut une clé SSH qui le lit, voir
[docs/deploy-dokploy.md](docs/deploy-dokploy.md)). Ce dépôt l'utilise sans le redéfinir.

## Contenu

| Chemin | Rôle |
|---|---|
| `crates/relay-common` | configuration, logs JSON, métriques, limites par IP, arrêt propre |
| `crates/relay-sni` | relais SNI : PROXY protocol v2, lecture du ClientHello, tunnels multiplexés |
| `crates/relay-push` | relais push : `POST /v1/push`, quotas, APNs, FCM |
| `fuzz/` | cibles `cargo-fuzz` des décodeurs exposés au réseau |
| `docs/` | déploiement ([docs/deploy-dokploy.md](docs/deploy-dokploy.md)), plans |

## Développement

```sh
cargo test --workspace                                 # avec une fausse maison, un faux APNs et un faux FCM
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check && cargo audit                        # licences, sources, avis de sécurité
(cd fuzz && cargo +nightly fuzz run client_hello)      # aussi : proxy_protocol, frames, push_request, tunnel_session
```

Images (binaires statiques musl, image `scratch`) :

```sh
scripts/vendor.sh                                      # sources vendues : build hors ligne
docker build --target relay-sni  -t agendo-relay-sni  .
docker build --target relay-push -t agendo-relay-push .
```

La CI (`.github/workflows/ci.yml`) teste, analyse, fait tourner le fuzzing, puis, sur `main`,
pousse `ghcr.io/charlyhue/agendo-relay-sni` et `ghcr.io/charlyhue/agendo-relay-push` étiquetées
par SHA et appelle les webhooks de Dokploy.

La configuration passe uniquement par des variables d'environnement, décrites dans
[docs/deploy-dokploy.md](docs/deploy-dokploy.md). Rien de propre à un déploiement (domaine,
clé, seuil) n'est écrit dans le code.

## Sécurité

Voir [SECURITY.md](SECURITY.md) pour signaler une vulnérabilité.
