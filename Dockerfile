# Images des relais d'Agendo Access : binaires statiques (musl) dans une image `scratch`.
#
#   scripts/vendor.sh
#   docker build --target relay-sni  -t agendo-relay-sni  .
#   docker build --target relay-push -t agendo-relay-push .
#
# Le build se fait hors ligne, sur les sources vendues par `scripts/vendor.sh` : la dépendance
# Git vers le socle (privé) ne demande aucune clé dans l'image.

ARG RUST_IMAGE=rust:1-alpine

FROM ${RUST_IMAGE} AS chef
# musl-dev : édition statique (et compilation de ring).
RUN apk add --no-cache musl-dev \
 && cargo install cargo-chef --locked --version ^0.1
WORKDIR /app

FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates crates
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY vendor vendor
COPY docker/cargo-vendor.toml .cargo/config.toml
COPY --from=planner /app/recipe.json recipe.json
# Couche des dépendances : recompilée seulement si Cargo.lock ou les manifestes changent.
RUN cargo chef cook --release --locked --offline --recipe-path recipe.json
COPY Cargo.toml Cargo.lock ./
COPY crates crates
RUN cargo build --release --locked --offline --bin relay-sni --bin relay-push \
 && for bin in relay-sni relay-push; do \
      if ldd "target/release/$bin" 2>/dev/null | grep -q '=>'; then echo "$bin n'est pas statique" >&2; exit 1; fi; \
    done

FROM scratch AS relay-sni
LABEL org.opencontainers.image.title="agendo-relay-sni" \
      org.opencontainers.image.description="Relais SNI d'Agendo Access" \
      org.opencontainers.image.source="https://github.com/charlyhue/agendo-access-relays"
COPY --from=builder /app/target/release/relay-sni /relay-sni
USER 65534:65534
# 8443 : public (passthrough + PROXY v2) ; 9443 : tunnels ; 9100 : métriques internes.
EXPOSE 8443 9443 9100
ENTRYPOINT ["/relay-sni"]

FROM scratch AS relay-push
LABEL org.opencontainers.image.title="agendo-relay-push" \
      org.opencontainers.image.description="Relais push d'Agendo Access" \
      org.opencontainers.image.source="https://github.com/charlyhue/agendo-access-relays"
COPY --from=builder /app/target/release/relay-push /relay-push
USER 65534:65534
# 8080 : POST /v1/push ; 9100 : métriques internes.
EXPOSE 8080 9100
ENTRYPOINT ["/relay-push"]
