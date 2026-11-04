//! Relais SNI d'**Agendo Access**.
//!
//! Deux ports :
//!
//! - **public** (8443, derrière Traefik en passthrough, PROXY protocol v2 obligatoire) : lit le
//!   ClientHello, trouve la maison qui sert le nom demandé, ouvre un flux dans son tunnel,
//!   rejoue les octets déjà lus puis recopie dans les deux sens, **sans déchiffrer** ;
//! - **tunnels** (9443, TLS terminé par Traefik) : poignée de main `HELLO`…`READY`, puis
//!   multiplexeur à trames avec contrôle de flux par flux.
//!
//! Le relais ne détient aucun secret et n'ouvre aucune connexion sortante.

pub mod proxy_protocol;
