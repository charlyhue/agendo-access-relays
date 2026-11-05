# Agendo Access : relais, consignes pour l'agent

Ce dépôt contient les deux relais d'Agendo Access (`relay-sni`, `relay-push`) et leur crate
commun. La spécification de référence est
`docs/superpowers/specs/2026-11-04-agendo-access-design.md` dans le dépôt du socle
(`charlyhue/agendo`, branche `main`). Elle fait foi, surtout les sections « Relais »,
« Protocole commun », « Configuration Traefik » et « Sécurité ».

**Le dépôt deviendra public.** Il s'écrit dès maintenant comme s'il l'était déjà.

## Commandes

- `cargo test --workspace` : toute la suite (tests d'intégration compris, avec une fausse
  maison et un faux APNs/FCM, sans réseau extérieur).
- `cargo clippy --workspace --all-targets -- -D warnings` : doit rester sans warning.
- `cargo deny check` et `cargo audit` : licences, sources, avis de sécurité.
- `cargo +nightly fuzz run <cible>` dans `fuzz/` : décodeurs exposés au réseau et session de
  tunnel (`cargo +nightly fuzz list`).
- Le protocole commun est une dépendance Git **au tag** du socle
  (`ssh://git@github.com/charlyhue/agendo.git`, `tag = "v…"`), dans `Cargo.toml` et
  `fuzz/Cargo.toml`. Accès par SSH, Cargo passant par la CLI git (`.cargo/config.toml`) : l'agent
  SSH doit avoir une clé qui lit `charlyhue/agendo`. Monter de version : changer le tag aux deux
  endroits, puis `cargo update -p agendo-access-protocol` à la racine **et** dans `fuzz/`.
  Jamais de chemin local (`path`, `file://`) : le dépôt deviendra public.
- Rust est installé via rustup : si `cargo` est introuvable, `. ~/.cargo/env`.

## Règles

- Les skills superpowers s'invoquent avant d'agir dès qu'ils s'appliquent. Consigne d'avancer
  sans questions : la spec fait foi, puis `writing-plans`, `test-driven-development`,
  `verification-before-completion`.
- Les points **[à trancher]** ne se décident pas seul : on prend le choix par défaut indiqué,
  on le signale et on le liste dans la PR.
- **Tout en français** : messages de log, commentaires, documentation, messages d'erreur.
- **Aucun secret** dans le code, Git, un fichier `.env` ni les logs. Les secrets du relais push
  (clé APNs `.p8`, compte de service FCM) sont des **fichiers montés**, désignés par des
  variables d'environnement. Le relais SNI n'a aucun secret.
- Les logs ne contiennent ni secret ni contenu : pas de jeton, pas de signature, pas de jeton
  de téléphone, pas de chiffré, pas d'octets d'un flux.
- **Configuration par variables d'environnement** uniquement. Aucun domaine, aucune clé et
  aucun seuil anti-abus en dur : une valeur par défaut documentée, toujours modifiable.
- Le protocole (trames, jetons, signatures, types du push) vient du crate
  `agendo-access-protocol` du socle et ne se redéfinit pas ici. Un besoin ou un désaccord sur
  le protocole se règle dans ce crate et dans la spec, côté socle. Ici, on le note dans la PR.
- Données réseau : aucun `unwrap`/`expect`/indexation qui puisse paniquer sur une donnée
  reçue. Chaque lecture a une taille maximale et un délai. Les connexions sont limitées par IP
  et au total. Tout décodeur exposé au réseau a sa cible de fuzzing dans `fuzz/`.
- Le relais SNI n'ouvre **aucune** connexion sortante : ce n'est pas un proxy ouvert.
