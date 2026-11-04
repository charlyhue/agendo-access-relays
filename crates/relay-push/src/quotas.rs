//! Quotas de notifications, d'après le jeton push de chaque maison : par heure (tous niveaux)
//! et alertes critiques par jour. Compteurs **en mémoire, par instance** : approximatifs si
//! plusieurs relais push servent les mêmes maisons, perdus au redémarrage (choix de la spec).
//!
//! Fenêtres fixes alignées sur l'heure et le jour UTC. La carte est bornée : au-delà de
//! `max_houses` maisons suivies, les entrées périmées sont purgées ; si elle reste pleine, la
//! demande est refusée (mémoire bornée avant tout).

use std::{
    collections::HashMap,
    sync::{Mutex, PoisonError},
};

use agendo_access_protocol::{push::PushLevel, token::Quotas};

/// Raison d'un refus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum QuotaExceeded {
    #[error("quota horaire de notifications atteint")]
    Hourly,
    #[error("quota quotidien d'alertes critiques atteint")]
    CriticalDaily,
    #[error("trop de maisons suivies par ce relais")]
    Full,
}

#[derive(Debug, Clone, Copy)]
struct Counters {
    hour: i64,
    in_hour: u32,
    day: i64,
    critical_in_day: u32,
}

/// Compteurs de toutes les maisons.
#[derive(Debug)]
pub struct QuotaBook {
    max_houses: usize,
    houses: Mutex<HashMap<String, Counters>>,
}

impl QuotaBook {
    pub fn new(max_houses: usize) -> Self {
        Self { max_houses, houses: Mutex::default() }
    }

    /// Compte une notification de `house` au niveau `level` à l'instant `now`, si les quotas
    /// du jeton le permettent.
    pub fn check(&self, house: &str, quotas: Quotas, level: PushLevel, now: i64) -> Result<(), QuotaExceeded> {
        let (hour, day) = (now.div_euclid(3600), now.div_euclid(86_400));
        let mut houses = self.houses.lock().unwrap_or_else(PoisonError::into_inner);
        if !houses.contains_key(house) && houses.len() >= self.max_houses {
            // Une entrée d'une heure et d'un jour passés ne limite plus rien.
            houses.retain(|_, c| c.hour == hour || c.day == day);
            if houses.len() >= self.max_houses {
                return Err(QuotaExceeded::Full);
            }
        }
        let c = houses.entry(house.to_owned()).or_insert(Counters { hour, in_hour: 0, day, critical_in_day: 0 });
        if c.hour != hour {
            (c.hour, c.in_hour) = (hour, 0);
        }
        if c.day != day {
            (c.day, c.critical_in_day) = (day, 0);
        }
        if c.in_hour >= quotas.per_hour {
            return Err(QuotaExceeded::Hourly);
        }
        let critical = level == PushLevel::Critical;
        if critical && c.critical_in_day >= quotas.critical_per_day {
            return Err(QuotaExceeded::CriticalDaily);
        }
        c.in_hour += 1;
        if critical {
            c.critical_in_day += 1;
        }
        Ok(())
    }

    /// Maisons suivies.
    pub fn len(&self) -> usize {
        self.houses.lock().unwrap_or_else(PoisonError::into_inner).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const HOUR: i64 = 3600;
    const DAY: i64 = 86_400;
    /// Début d'un jour UTC.
    const T0: i64 = 1_792_972_800;
    const Q: Quotas = Quotas { per_hour: 3, critical_per_day: 2 };

    #[test]
    fn hourly_quota_counts_all_levels() {
        let b = QuotaBook::new(10);
        assert_eq!(b.check("m1", Q, PushLevel::Active, T0), Ok(()));
        assert_eq!(b.check("m1", Q, PushLevel::Passive, T0 + 1), Ok(()));
        assert_eq!(b.check("m1", Q, PushLevel::Critical, T0 + 2), Ok(()));
        assert_eq!(b.check("m1", Q, PushLevel::Active, T0 + 3), Err(QuotaExceeded::Hourly));
        assert_eq!(b.check("m1", Q, PushLevel::Active, T0 + HOUR), Ok(()), "heure suivante");
    }

    #[test]
    fn critical_quota_per_day() {
        let b = QuotaBook::new(10);
        assert_eq!(b.check("m1", Q, PushLevel::Critical, T0), Ok(()));
        assert_eq!(b.check("m1", Q, PushLevel::Critical, T0 + HOUR), Ok(()));
        assert_eq!(b.check("m1", Q, PushLevel::Critical, T0 + 2 * HOUR), Err(QuotaExceeded::CriticalDaily));
        assert_eq!(b.check("m1", Q, PushLevel::TimeSensitive, T0 + 2 * HOUR), Ok(()), "les autres niveaux passent");
        assert_eq!(b.check("m1", Q, PushLevel::Critical, T0 + DAY), Ok(()), "jour suivant");
    }

    #[test]
    fn refused_attempts_are_not_counted() {
        let b = QuotaBook::new(10);
        let q = Quotas { per_hour: 10, critical_per_day: 1 };
        assert_eq!(b.check("m1", q, PushLevel::Critical, T0), Ok(()));
        for _ in 0..5 {
            assert_eq!(b.check("m1", q, PushLevel::Critical, T0), Err(QuotaExceeded::CriticalDaily));
        }
        for _ in 0..9 {
            assert_eq!(b.check("m1", q, PushLevel::Active, T0), Ok(()), "les refus n'ont pas mangé le quota horaire");
        }
    }

    #[test]
    fn houses_are_independent() {
        let b = QuotaBook::new(10);
        let q = Quotas { per_hour: 1, critical_per_day: 1 };
        assert_eq!(b.check("m1", q, PushLevel::Active, T0), Ok(()));
        assert_eq!(b.check("m2", q, PushLevel::Active, T0), Ok(()));
        assert_eq!(b.check("m1", q, PushLevel::Active, T0), Err(QuotaExceeded::Hourly));
    }

    #[test]
    fn zero_quota_refuses_everything() {
        let b = QuotaBook::new(10);
        let q = Quotas { per_hour: 0, critical_per_day: 0 };
        assert_eq!(b.check("m1", q, PushLevel::Active, T0), Err(QuotaExceeded::Hourly));
    }

    #[test]
    fn map_is_bounded_and_purged() {
        let b = QuotaBook::new(2);
        assert_eq!(b.check("m1", Q, PushLevel::Active, T0), Ok(()));
        assert_eq!(b.check("m2", Q, PushLevel::Active, T0), Ok(()));
        assert_eq!(b.check("m3", Q, PushLevel::Active, T0), Err(QuotaExceeded::Full));
        assert_eq!(b.check("m1", Q, PushLevel::Active, T0), Ok(()), "maison déjà suivie");
        // Le lendemain, les entrées d'hier sont périmées et purgées.
        assert_eq!(b.check("m3", Q, PushLevel::Active, T0 + DAY), Ok(()));
        assert_eq!(b.len(), 1);
    }
}
