#!/bin/sh
# En CI : la dépendance vers le protocole du socle pointe, en développement, sur le dépôt
# local (`file:///Users/chue/workspace/agendo`). Ce script la remplace par l'URL GitHub (SSH),
# au **même commit** que celui figé dans les Cargo.lock. La clé de déploiement en lecture sur
# `charlyhue/agendo` doit être chargée dans l'agent SSH (voir docs/deploy-dokploy.md).
set -eu
cd "$(dirname "$0")/.."
from='file:///Users/chue/workspace/agendo'
to='ssh://git@github.com/charlyhue/agendo.git'
for f in Cargo.toml Cargo.lock fuzz/Cargo.toml fuzz/Cargo.lock; do
    sed "s#${from}#${to}#g" "$f" > "$f.tmp"
    mv "$f.tmp" "$f"
done
grep -h 'charlyhue/agendo.git' Cargo.lock | sort -u >&2
