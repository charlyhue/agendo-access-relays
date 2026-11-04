//! Heure Unix, pour la vérification des jetons et des signatures.

use std::time::{SystemTime, UNIX_EPOCH};

/// Secondes Unix actuelles (0 si l'horloge est avant 1970).
pub fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX)).unwrap_or(0)
}
