//! Configuration du relais push, par variables d'environnement. Les secrets (clé APNs `.p8`,
//! compte de service FCM) sont des **fichiers montés** : les variables n'en donnent que le
//! chemin.
//!
//! | Variable | Défaut | Rôle |
//! |---|---|---|
//! | `RELAY_TRUSTED_KEYS` | (requis) | clés publiques du plan de contrôle, `kid=clé,kid2=clé2` |
//! | `RELAY_PUSH_ADDR` | `0.0.0.0:8080` | écoute HTTP (derrière Traefik) |
//! | `RELAY_METRICS_ADDR` | `127.0.0.1:9100` | métriques ; vide : désactivées |
//! | `RELAY_PUSH_APNS_KEY_FILE` | — | clé `.p8` ; posée, APNs est activé |
//! | `RELAY_PUSH_APNS_KEY_ID` | (requis avec APNs) | identifiant de la clé |
//! | `RELAY_PUSH_APNS_TEAM_ID` | (requis avec APNs) | équipe Apple |
//! | `RELAY_PUSH_APNS_TOPIC` | (requis avec APNs) | identifiant de l'app |
//! | `RELAY_PUSH_APNS_ENV` | (requis avec APNs) | `production` ou `sandbox` |
//! | `RELAY_PUSH_APNS_URL` | selon `ENV` | autre adresse d'APNs (essais) |
//! | `RELAY_PUSH_FCM_SERVICE_ACCOUNT_FILE` | — | compte de service JSON ; posé, FCM est activé |
//! | `RELAY_PUSH_FCM_URL` | `https://fcm.googleapis.com` | autre adresse de FCM (essais) |
//! | `RELAY_PUSH_MAX_BODY` | `8192` | taille maximale du corps, en octets |
//! | `RELAY_PUSH_TIMEOUT_SECS` | `10` | délai d'une remise à APNs ou FCM |
//! | `RELAY_PUSH_MAX_CONCURRENT` | `256` | requêtes traitées en même temps |
//! | `RELAY_PUSH_MAX_HOUSES` | `100000` | maisons suivies par les quotas |

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use agendo_access_protocol::keys::TrustedKeys;
use relay_common::config::{ConfigError, Env};

use crate::{apns, fcm};

/// Seuils.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushLimits {
    pub max_body: usize,
    pub upstream_timeout: Duration,
    pub max_concurrent: usize,
    pub max_houses: usize,
}

impl Default for PushLimits {
    fn default() -> Self {
        Self { max_body: 8192, upstream_timeout: Duration::from_secs(10), max_concurrent: 256, max_houses: 100_000 }
    }
}

/// Réglages APNs (la clé est lue au démarrage).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApnsSettings {
    pub key_file: PathBuf,
    pub key_id: String,
    pub team_id: String,
    pub topic: String,
    pub base_url: String,
}

/// Réglages FCM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FcmSettings {
    pub service_account_file: PathBuf,
    pub base_url: String,
}

#[derive(Debug, Clone)]
pub struct PushConfig {
    pub addr: SocketAddr,
    pub metrics_addr: Option<SocketAddr>,
    pub trusted_keys: TrustedKeys,
    pub apns: Option<ApnsSettings>,
    pub fcm: Option<FcmSettings>,
    pub limits: PushLimits,
}

impl PushConfig {
    pub fn from_env(env: &Env) -> Result<Self, ConfigError> {
        let addr = |name: &str, default: &str| -> Result<SocketAddr, ConfigError> {
            env.get(name).unwrap_or(default).parse().map_err(|_| ConfigError::invalid(name, "adresse:port attendu"))
        };
        let metrics_addr = if env.vars_contains("RELAY_METRICS_ADDR") && env.get("RELAY_METRICS_ADDR").is_none() {
            None
        } else {
            Some(addr("RELAY_METRICS_ADDR", "127.0.0.1:9100")?)
        };
        let apns = match env.get("RELAY_PUSH_APNS_KEY_FILE") {
            None => None,
            Some(file) => {
                let base_url = match env.get("RELAY_PUSH_APNS_URL") {
                    Some(url) => url.to_owned(),
                    None => match env.required("RELAY_PUSH_APNS_ENV")?.as_str() {
                        "production" => apns::PRODUCTION_URL.to_owned(),
                        "sandbox" => apns::SANDBOX_URL.to_owned(),
                        _ => return Err(ConfigError::invalid("RELAY_PUSH_APNS_ENV", "production ou sandbox attendu")),
                    },
                };
                Some(ApnsSettings {
                    key_file: PathBuf::from(file),
                    key_id: env.required("RELAY_PUSH_APNS_KEY_ID")?,
                    team_id: env.required("RELAY_PUSH_APNS_TEAM_ID")?,
                    topic: env.required("RELAY_PUSH_APNS_TOPIC")?,
                    base_url,
                })
            }
        };
        let fcm = env.get("RELAY_PUSH_FCM_SERVICE_ACCOUNT_FILE").map(|file| FcmSettings {
            service_account_file: PathBuf::from(file),
            base_url: env.get("RELAY_PUSH_FCM_URL").unwrap_or(fcm::FCM_URL).to_owned(),
        });
        if apns.is_none() && fcm.is_none() {
            return Err(ConfigError::Missing("RELAY_PUSH_APNS_KEY_FILE ou RELAY_PUSH_FCM_SERVICE_ACCOUNT_FILE".into()));
        }
        let d = PushLimits::default();
        let positive = |name: &str, default: usize| -> Result<usize, ConfigError> {
            match env.parse_or(name, default)? {
                0 => Err(ConfigError::invalid(name, "doit être supérieur à 0")),
                v => Ok(v),
            }
        };
        let limits = PushLimits {
            max_body: positive("RELAY_PUSH_MAX_BODY", d.max_body)?,
            upstream_timeout: Duration::from_secs(positive("RELAY_PUSH_TIMEOUT_SECS", 10)? as u64),
            max_concurrent: positive("RELAY_PUSH_MAX_CONCURRENT", d.max_concurrent)?,
            max_houses: positive("RELAY_PUSH_MAX_HOUSES", d.max_houses)?,
        };
        Ok(Self {
            addr: addr("RELAY_PUSH_ADDR", "0.0.0.0:8080")?,
            metrics_addr,
            trusted_keys: env.trusted_keys("RELAY_TRUSTED_KEYS")?,
            apns,
            fcm,
            limits,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use agendo_access_protocol::{SigningKey, keys::encode_public_key};

    use super::*;

    fn keys() -> String {
        format!("k1={}", encode_public_key(&SigningKey::from_bytes(&[1; 32]).verifying_key()))
    }

    #[test]
    fn apns_production_and_defaults() {
        let k = keys();
        let c = PushConfig::from_env(&Env::from_pairs(&[
            ("RELAY_TRUSTED_KEYS", &k),
            ("RELAY_PUSH_APNS_KEY_FILE", "/run/secrets/apns.p8"),
            ("RELAY_PUSH_APNS_KEY_ID", "KEYID12345"),
            ("RELAY_PUSH_APNS_TEAM_ID", "TEAM123456"),
            ("RELAY_PUSH_APNS_TOPIC", "fr.exemple.agendo"),
            ("RELAY_PUSH_APNS_ENV", "production"),
        ]))
        .unwrap();
        assert_eq!(c.apns.unwrap().base_url, apns::PRODUCTION_URL);
        assert!(c.fcm.is_none());
        assert_eq!(c.addr, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(c.limits, PushLimits::default());
    }

    #[test]
    fn fcm_alone_and_errors() {
        let k = keys();
        let c = PushConfig::from_env(&Env::from_pairs(&[("RELAY_TRUSTED_KEYS", &k), ("RELAY_PUSH_FCM_SERVICE_ACCOUNT_FILE", "/run/secrets/fcm.json")])).unwrap();
        assert_eq!(c.fcm.unwrap().base_url, fcm::FCM_URL);
        assert!(matches!(PushConfig::from_env(&Env::from_pairs(&[("RELAY_TRUSTED_KEYS", &k)])), Err(ConfigError::Missing(_))), "ni APNs ni FCM");
        let missing_env = PushConfig::from_env(&Env::from_pairs(&[
            ("RELAY_TRUSTED_KEYS", &k),
            ("RELAY_PUSH_APNS_KEY_FILE", "/k.p8"),
            ("RELAY_PUSH_APNS_KEY_ID", "a"),
            ("RELAY_PUSH_APNS_TEAM_ID", "b"),
            ("RELAY_PUSH_APNS_TOPIC", "c"),
        ]));
        assert_eq!(missing_env.unwrap_err(), ConfigError::Missing("RELAY_PUSH_APNS_ENV".into()));
        let zero = PushConfig::from_env(&Env::from_pairs(&[
            ("RELAY_TRUSTED_KEYS", &k),
            ("RELAY_PUSH_FCM_SERVICE_ACCOUNT_FILE", "/f.json"),
            ("RELAY_PUSH_MAX_BODY", "0"),
        ]));
        assert!(matches!(zero, Err(ConfigError::Invalid { .. })));
    }
}
