//! Configuration par variables d'environnement.
//!
//! Les erreurs nomment la variable fautive, jamais sa valeur : une valeur mal placée pourrait
//! être un secret.

use std::{collections::BTreeMap, str::FromStr};

use agendo_access_protocol::keys::TrustedKeys;

/// Erreur de configuration : la variable en cause et la raison, sans la valeur.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("variable d'environnement {0} manquante")]
    Missing(String),
    #[error("variable d'environnement {name} illisible : {reason}")]
    Invalid { name: String, reason: String },
}

impl ConfigError {
    pub fn invalid(name: &str, reason: impl Into<String>) -> Self {
        Self::Invalid { name: name.to_owned(), reason: reason.into() }
    }
}

/// Instantané des variables d'environnement.
#[derive(Debug, Clone, Default)]
pub struct Env {
    vars: BTreeMap<String, String>,
}

impl Env {
    /// Variables du processus (celles qui ne sont pas de l'UTF-8 sont ignorées).
    pub fn from_os() -> Self {
        Self { vars: std::env::vars_os().filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?))).collect() }
    }

    /// Variables données (tests).
    pub fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        Self { vars: pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect() }
    }

    /// Valeur, si la variable est posée et non vide (blancs autour retirés).
    pub fn get(&self, name: &str) -> Option<&str> {
        self.vars.get(name).map(|v| v.trim()).filter(|v| !v.is_empty())
    }

    /// Valeur obligatoire.
    pub fn required(&self, name: &str) -> Result<String, ConfigError> {
        self.get(name).map(str::to_owned).ok_or_else(|| ConfigError::Missing(name.to_owned()))
    }

    /// Valeur lue par `FromStr`, ou `default` si la variable est absente.
    pub fn parse_or<T: FromStr>(&self, name: &str, default: T) -> Result<T, ConfigError> {
        match self.get(name) {
            None => Ok(default),
            Some(v) => v.parse().map_err(|_| ConfigError::invalid(name, "format inattendu")),
        }
    }

    /// Booléen : `on`/`off`, `true`/`false`, `1`/`0`, `oui`/`non`.
    pub fn flag_or(&self, name: &str, default: bool) -> Result<bool, ConfigError> {
        match self.get(name).map(str::to_ascii_lowercase).as_deref() {
            None => Ok(default),
            Some("on" | "true" | "1" | "oui") => Ok(true),
            Some("off" | "false" | "0" | "non") => Ok(false),
            Some(_) => Err(ConfigError::invalid(name, "on ou off attendu")),
        }
    }

    /// Clés publiques de confiance du plan de contrôle : `kid=clé,kid2=clé2`, au moins une.
    pub fn trusted_keys(&self, name: &str) -> Result<TrustedKeys, ConfigError> {
        let keys = TrustedKeys::parse_list(&self.required(name)?).map_err(|e| ConfigError::invalid(name, e.to_string()))?;
        if keys.is_empty() {
            return Err(ConfigError::invalid(name, "aucune clé"));
        }
        Ok(keys)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use agendo_access_protocol::{SigningKey, keys::encode_public_key};

    use super::*;

    fn public(seed: u8) -> String {
        encode_public_key(&SigningKey::from_bytes(&[seed; 32]).verifying_key())
    }

    #[test]
    fn required_and_defaults() {
        let env = Env::from_pairs(&[("A", " x "), ("VIDE", "  "), ("N", "42")]);
        assert_eq!(env.required("A").unwrap(), "x");
        assert_eq!(env.required("VIDE"), Err(ConfigError::Missing("VIDE".into())));
        assert_eq!(env.required("ABSENTE"), Err(ConfigError::Missing("ABSENTE".into())));
        assert_eq!(env.parse_or("N", 1u32).unwrap(), 42);
        assert_eq!(env.parse_or("ABSENTE", 7u32).unwrap(), 7);
    }

    #[test]
    fn invalid_value_names_the_variable_not_the_value() {
        let env = Env::from_pairs(&[("N", "secret-mal-place")]);
        let err = env.parse_or("N", 1u32).unwrap_err();
        assert_eq!(err, ConfigError::invalid("N", "format inattendu"));
        assert!(!err.to_string().contains("secret"), "{err}");
    }

    #[test]
    fn flags() {
        let env = Env::from_pairs(&[("A", "OFF"), ("B", "oui"), ("C", "peut-être")]);
        assert!(!env.flag_or("A", true).unwrap());
        assert!(env.flag_or("B", false).unwrap());
        assert!(env.flag_or("ABSENTE", true).unwrap());
        assert!(env.flag_or("C", true).is_err());
    }

    #[test]
    fn trusted_keys_list() {
        let env = Env::from_pairs(&[("K", &format!("k1={},k2={}", public(1), public(2))), ("VIDE", ","), ("MAL", "k1=abc")]);
        assert_eq!(env.trusted_keys("K").unwrap().len(), 2);
        assert_eq!(env.trusted_keys("VIDE"), Err(ConfigError::invalid("VIDE", "aucune clé")));
        assert!(matches!(env.trusted_keys("MAL"), Err(ConfigError::Invalid { .. })));
        assert_eq!(env.trusted_keys("ABSENTE"), Err(ConfigError::Missing("ABSENTE".into())));
    }
}
