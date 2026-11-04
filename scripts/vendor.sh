#!/bin/sh
# Vend les sources des dépendances (crates.io et protocole du socle) dans `vendor/`, et écrit
# la configuration Cargo qui les utilise (`docker/cargo-vendor.toml`). L'image Docker se
# construit ensuite hors ligne : aucune clé ni accès réseau pendant le build.
#
# Usage : scripts/vendor.sh   (puis docker build …)
set -eu
cd "$(dirname "$0")/.."
rm -rf vendor
cargo vendor --locked --versioned-dirs vendor > docker/cargo-vendor.toml
echo "Sources vendues dans vendor/ ($(du -sh vendor | cut -f1)), configuration dans docker/cargo-vendor.toml" >&2
