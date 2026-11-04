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
le crate `agendo-access-protocol` du socle Agendo. Ce dépôt l'utilise sans le redéfinir.

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
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

La configuration passe uniquement par des variables d'environnement, décrites dans
[docs/deploy-dokploy.md](docs/deploy-dokploy.md). Rien de propre à un déploiement (domaine,
clé, seuil) n'est écrit dans le code.

## Sécurité

Voir [SECURITY.md](SECURITY.md) pour signaler une vulnérabilité.
