//! Configuration du relais SNI, par variables d'environnement.
//!
//! | Variable | Défaut | Rôle |
//! |---|---|---|
//! | `RELAY_SNI_ZONE` | (requis) | `ZONE_MAISONS` : seuls les jetons d'un hôte `<16 base32>.<zone>` sont admis |
//! | `RELAY_TRUSTED_KEYS` | (requis) | clés publiques du plan de contrôle, `kid=clé,kid2=clé2` |
//! | `RELAY_SNI_PROXY_PROTOCOL` | `on` | PROXY protocol v2 exigé sur les deux ports ; `off` : mode autonome |
//! | `RELAY_SNI_PROXY_FROM` | (requis si `on`) | réseaux autorisés à l'envoyer (CIDR séparés par des virgules) |
//! | `RELAY_SNI_PUBLIC_ADDR` | `0.0.0.0:8443` | port public (passthrough de Traefik) |
//! | `RELAY_SNI_TUNNEL_ADDR` | `0.0.0.0:9443` | port des tunnels (TLS terminé par Traefik) |
//! | `RELAY_METRICS_ADDR` | `127.0.0.1:9100` | métriques ; vide : désactivées |
//! | `RELAY_SNI_MAX_CONNECTIONS` | `4096` | connexions publiques simultanées |
//! | `RELAY_SNI_MAX_CONNECTIONS_PER_IP` | `64` | connexions publiques simultanées par IP (/64 en IPv6) |
//! | `RELAY_SNI_MAX_TUNNELS` | `4096` | tunnels simultanés |
//! | `RELAY_SNI_MAX_TUNNELS_PER_IP` | `8` | tunnels simultanés par IP |
//! | `RELAY_SNI_MAX_STREAMS_PER_TUNNEL` | `1024` | flux ouverts par tunnel |
//! | `RELAY_SNI_INITIAL_WINDOW` | `262144` | fenêtre initiale par flux, en octets (≤ 16 Mio) |
//! | `RELAY_SNI_HELLO_TIMEOUT_SECS` | `10` | PROXY + ClientHello du client |
//! | `RELAY_SNI_HANDSHAKE_TIMEOUT_SECS` | `10` | de la connexion d'une maison à `READY` |
//! | `RELAY_SNI_PING_INTERVAL_SECS` | `25` | ping des tunnels |
//! | `RELAY_SNI_WRITE_TIMEOUT_SECS` | `30` | écriture bloquée vers une maison ou un client |
//! | `RELAY_SNI_SHUTDOWN_GRACE_SECS` | `5` | délai entre `GOAWAY` et l'arrêt |

use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use agendo_access_protocol::{
    frame::{DEFAULT_INITIAL_WINDOW, HANDSHAKE_TIMEOUT_SECS, MAX_STREAMS, MAX_WINDOW, PING_INTERVAL_SECS},
    keys::TrustedKeys,
};
use relay_common::config::{ConfigError, Env};

/// Plus petite fenêtre initiale admise : une trame `DATA` de 16 Kio doit pouvoir passer.
pub const MIN_INITIAL_WINDOW: u32 = 16 * 1024;

/// Réseau autorisé (`10.0.1.0/24`, `fd00::/8`, ou une adresse seule).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// L'adresse est-elle dans ce réseau ? Une IPv4 mappée en IPv6 compte comme IPv4.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        };
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => masked(u128::from(u32::from(net)), u128::from(u32::from(ip)), 32, self.prefix),
            (IpAddr::V6(net), IpAddr::V6(ip)) => masked(u128::from(net), u128::from(ip), 128, self.prefix),
            _ => false,
        }
    }
}

/// Les `prefix` premiers bits (sur `width`) de `a` et `b` sont-ils égaux ?
fn masked(a: u128, b: u128, width: u8, prefix: u8) -> bool {
    let host_bits = u32::from(width - prefix);
    (a ^ b).checked_shr(host_bits).unwrap_or(0) == 0
}

impl FromStr for Cidr {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, ()> {
        let (addr, prefix) = match s.trim().split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (s.trim(), None),
        };
        let network: IpAddr = addr.parse().map_err(|_| ())?;
        let width = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => width,
            Some(p) => p.parse::<u8>().ok().filter(|p| *p <= width).ok_or(())?,
        };
        Ok(Self { network, prefix })
    }
}

/// Politique du PROXY protocol, commune aux deux ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyPolicy {
    /// En-tête v2 exigé, seulement de ces réseaux.
    Required(Vec<Cidr>),
    /// Pas d'amont (mode autonome) : l'adresse du pair TCP est celle du client.
    Off,
}

impl ProxyPolicy {
    /// Ce pair peut-il envoyer un en-tête PROXY (ou se connecter, si l'en-tête est exigé) ?
    pub fn allows_peer(&self, peer: IpAddr) -> bool {
        match self {
            ProxyPolicy::Required(nets) => nets.iter().any(|n| n.contains(peer)),
            ProxyPolicy::Off => true,
        }
    }
}

/// Seuils et délais.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    pub max_tunnels: usize,
    pub max_tunnels_per_ip: usize,
    pub max_streams_per_tunnel: usize,
    pub initial_window: u32,
    pub hello_timeout: Duration,
    pub handshake_timeout: Duration,
    pub ping_interval: Duration,
    pub write_timeout: Duration,
    pub shutdown_grace: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 4096,
            max_connections_per_ip: 64,
            max_tunnels: 4096,
            max_tunnels_per_ip: 8,
            max_streams_per_tunnel: MAX_STREAMS,
            initial_window: DEFAULT_INITIAL_WINDOW,
            hello_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(HANDSHAKE_TIMEOUT_SECS.into()),
            ping_interval: Duration::from_secs(PING_INTERVAL_SECS.into()),
            write_timeout: Duration::from_secs(30),
            shutdown_grace: Duration::from_secs(5),
        }
    }
}

/// Configuration complète du relais SNI.
#[derive(Debug, Clone)]
pub struct SniConfig {
    /// `ZONE_MAISONS`, en minuscules, sans point au début ni à la fin.
    pub zone: String,
    pub trusted_keys: TrustedKeys,
    pub proxy: ProxyPolicy,
    pub public_addr: SocketAddr,
    pub tunnel_addr: SocketAddr,
    pub metrics_addr: Option<SocketAddr>,
    pub limits: Limits,
}

impl SniConfig {
    pub fn from_env(env: &Env) -> Result<Self, ConfigError> {
        let zone = env.required("RELAY_SNI_ZONE")?.trim_matches('.').to_ascii_lowercase();
        if zone.is_empty() || !zone.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.') {
            return Err(ConfigError::invalid("RELAY_SNI_ZONE", "nom de domaine attendu"));
        }
        let trusted_keys = env.trusted_keys("RELAY_TRUSTED_KEYS")?;
        let proxy = if env.flag_or("RELAY_SNI_PROXY_PROTOCOL", true)? {
            let list = env.required("RELAY_SNI_PROXY_FROM")?;
            let nets = list
                .split(',')
                .map(str::trim)
                .filter(|n| !n.is_empty())
                .map(|n| n.parse::<Cidr>())
                .collect::<Result<Vec<_>, ()>>()
                .map_err(|()| ConfigError::invalid("RELAY_SNI_PROXY_FROM", "réseau CIDR attendu (10.0.1.0/24)"))?;
            if nets.is_empty() {
                return Err(ConfigError::Missing("RELAY_SNI_PROXY_FROM".into()));
            }
            ProxyPolicy::Required(nets)
        } else {
            ProxyPolicy::Off
        };
        let d = Limits::default();
        let count = |name: &str, default: usize| -> Result<usize, ConfigError> {
            let v = env.parse_or(name, default)?;
            if v == 0 {
                return Err(ConfigError::invalid(name, "doit être supérieur à 0"));
            }
            Ok(v)
        };
        let secs = |name: &str, default: Duration| -> Result<Duration, ConfigError> {
            let v: u64 = env.parse_or(name, default.as_secs())?;
            if v == 0 {
                return Err(ConfigError::invalid(name, "doit être supérieur à 0"));
            }
            Ok(Duration::from_secs(v))
        };
        let initial_window: u32 = env.parse_or("RELAY_SNI_INITIAL_WINDOW", d.initial_window)?;
        if !(MIN_INITIAL_WINDOW..=MAX_WINDOW).contains(&initial_window) {
            return Err(ConfigError::invalid("RELAY_SNI_INITIAL_WINDOW", "entre 16 Kio et 16 Mio"));
        }
        let limits = Limits {
            max_connections: count("RELAY_SNI_MAX_CONNECTIONS", d.max_connections)?,
            max_connections_per_ip: count("RELAY_SNI_MAX_CONNECTIONS_PER_IP", d.max_connections_per_ip)?,
            max_tunnels: count("RELAY_SNI_MAX_TUNNELS", d.max_tunnels)?,
            max_tunnels_per_ip: count("RELAY_SNI_MAX_TUNNELS_PER_IP", d.max_tunnels_per_ip)?,
            max_streams_per_tunnel: count("RELAY_SNI_MAX_STREAMS_PER_TUNNEL", d.max_streams_per_tunnel)?,
            initial_window,
            hello_timeout: secs("RELAY_SNI_HELLO_TIMEOUT_SECS", d.hello_timeout)?,
            handshake_timeout: secs("RELAY_SNI_HANDSHAKE_TIMEOUT_SECS", d.handshake_timeout)?,
            ping_interval: secs("RELAY_SNI_PING_INTERVAL_SECS", d.ping_interval)?,
            write_timeout: secs("RELAY_SNI_WRITE_TIMEOUT_SECS", d.write_timeout)?,
            shutdown_grace: secs("RELAY_SNI_SHUTDOWN_GRACE_SECS", d.shutdown_grace)?,
        };
        let addr = |name: &str, default: &str| -> Result<SocketAddr, ConfigError> {
            env.get(name).unwrap_or(default).parse().map_err(|_| ConfigError::invalid(name, "adresse:port attendu"))
        };
        // Posée mais vide : métriques désactivées.
        let metrics_addr = if env.vars_contains("RELAY_METRICS_ADDR") && env.get("RELAY_METRICS_ADDR").is_none() {
            None
        } else {
            Some(addr("RELAY_METRICS_ADDR", "127.0.0.1:9100")?)
        };
        Ok(Self {
            zone,
            trusted_keys,
            proxy,
            public_addr: addr("RELAY_SNI_PUBLIC_ADDR", "0.0.0.0:8443")?,
            tunnel_addr: addr("RELAY_SNI_TUNNEL_ADDR", "0.0.0.0:9443")?,
            metrics_addr,
            limits,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use agendo_access_protocol::{SigningKey, keys::encode_public_key};

    use super::*;

    fn cidr(s: &str) -> Cidr {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn keys() -> String {
        format!("k1={}", encode_public_key(&SigningKey::from_bytes(&[1; 32]).verifying_key()))
    }

    #[test]
    fn cidr_contains() {
        assert!(cidr("10.0.1.0/24").contains(ip("10.0.1.200")));
        assert!(!cidr("10.0.1.0/24").contains(ip("10.0.2.1")));
        assert!(cidr("10.0.1.0/24").contains(ip("::ffff:10.0.1.3")), "IPv4 mappée");
        assert!(cidr("172.16.0.0/12").contains(ip("172.31.255.255")));
        assert!(cidr("0.0.0.0/0").contains(ip("203.0.113.1")));
        assert!(!cidr("0.0.0.0/0").contains(ip("2001:db8::1")));
        assert!(cidr("fd00::/8").contains(ip("fd12::1")));
        assert!(cidr("127.0.0.1").contains(ip("127.0.0.1")));
        assert!(!cidr("127.0.0.1").contains(ip("127.0.0.2")));
        assert!(cidr("10.0.1.7/24").contains(ip("10.0.1.1")), "bits d'hôte ignorés");
    }

    #[test]
    fn cidr_refuses_garbage() {
        for bad in ["", "10.0.0.0/33", "fd00::/129", "10.0.0/8", "nimporte", "10.0.0.0/", "10.0.0.0/-1"] {
            assert!(bad.parse::<Cidr>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn from_env_defaults() {
        let env = Env::from_pairs(&[
            ("RELAY_SNI_ZONE", ".Maisons.Exemple.fr."),
            ("RELAY_TRUSTED_KEYS", &keys()),
            ("RELAY_SNI_PROXY_FROM", "10.0.1.0/24, fd00::/8"),
        ]);
        let c = SniConfig::from_env(&env).unwrap();
        assert_eq!(c.zone, "maisons.exemple.fr");
        assert_eq!(c.proxy, ProxyPolicy::Required(vec![cidr("10.0.1.0/24"), cidr("fd00::/8")]));
        assert_eq!(c.public_addr, "0.0.0.0:8443".parse().unwrap());
        assert_eq!(c.tunnel_addr, "0.0.0.0:9443".parse().unwrap());
        assert_eq!(c.metrics_addr, Some("127.0.0.1:9100".parse().unwrap()));
        assert_eq!(c.limits, Limits::default());
    }

    #[test]
    fn from_env_requires_zone_keys_and_proxy_sources() {
        let missing = |pairs: &[(&str, &str)], var: &str| {
            assert_eq!(SniConfig::from_env(&Env::from_pairs(pairs)).unwrap_err(), ConfigError::Missing(var.into()));
        };
        let k = keys();
        missing(&[("RELAY_TRUSTED_KEYS", &k), ("RELAY_SNI_PROXY_FROM", "10.0.0.0/8")], "RELAY_SNI_ZONE");
        missing(&[("RELAY_SNI_ZONE", "z.fr"), ("RELAY_SNI_PROXY_FROM", "10.0.0.0/8")], "RELAY_TRUSTED_KEYS");
        missing(&[("RELAY_SNI_ZONE", "z.fr"), ("RELAY_TRUSTED_KEYS", &k)], "RELAY_SNI_PROXY_FROM");
        let off = SniConfig::from_env(&Env::from_pairs(&[
            ("RELAY_SNI_ZONE", "z.fr"),
            ("RELAY_TRUSTED_KEYS", &k),
            ("RELAY_SNI_PROXY_PROTOCOL", "off"),
            ("RELAY_METRICS_ADDR", ""),
        ]))
        .unwrap();
        assert_eq!(off.proxy, ProxyPolicy::Off);
        assert_eq!(off.metrics_addr, None);
    }

    #[test]
    fn from_env_refuses_bad_values() {
        let k = keys();
        let base = [("RELAY_SNI_ZONE", "z.fr"), ("RELAY_TRUSTED_KEYS", k.as_str()), ("RELAY_SNI_PROXY_FROM", "10.0.0.0/8")];
        let with = |extra: (&'static str, &'static str)| {
            let mut pairs = base.to_vec();
            pairs.push(extra);
            SniConfig::from_env(&Env::from_pairs(&pairs))
        };
        assert!(matches!(with(("RELAY_SNI_PROXY_FROM", "10.0.0.0/8,pas-un-réseau")), Err(ConfigError::Invalid { .. })));
        assert!(matches!(with(("RELAY_SNI_INITIAL_WINDOW", "33554432")), Err(ConfigError::Invalid { .. })), "au-delà de 16 Mio");
        assert!(matches!(with(("RELAY_SNI_INITIAL_WINDOW", "100")), Err(ConfigError::Invalid { .. })), "trop petite");
        assert!(matches!(with(("RELAY_SNI_MAX_TUNNELS_PER_IP", "0")), Err(ConfigError::Invalid { .. })));
        assert!(matches!(with(("RELAY_SNI_ZONE", "a b")), Err(ConfigError::Invalid { .. })));
        assert!(matches!(with(("RELAY_SNI_PROXY_PROTOCOL", "peut-être")), Err(ConfigError::Invalid { .. })));
        assert_eq!(with(("RELAY_SNI_PING_INTERVAL_SECS", "5")).unwrap().limits.ping_interval, Duration::from_secs(5));
    }
}
