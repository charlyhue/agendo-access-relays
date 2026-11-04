//! Limite des connexions simultanées, par IP et au total.
//!
//! Une IPv6 est comptée par préfixe /64 : un client en obtient d'ordinaire un bloc entier, la
//! compter adresse par adresse ne limiterait rien.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
};

/// Compteur partagé des connexions ouvertes.
#[derive(Debug, Clone)]
pub struct IpLimiter {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    per_ip: usize,
    total: usize,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    total: usize,
    by_ip: HashMap<IpAddr, usize>,
}

/// Place réservée ; rendue au `Drop`.
#[derive(Debug)]
pub struct IpGuard {
    inner: Arc<Inner>,
    key: IpAddr,
}

/// Clé de comptage : l'IPv4 telle quelle (y compris sous forme IPv4 mappée), l'IPv6 réduite à
/// son /64.
pub fn ip_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::from([s[0], s[1], s[2], s[3], 0, 0, 0, 0])
            }
        },
    }
}

impl IpLimiter {
    pub fn new(per_ip: usize, total: usize) -> Self {
        Self { inner: Arc::new(Inner { per_ip, total, state: Mutex::default() }) }
    }

    /// Réserve une place pour `ip`, si les deux limites le permettent.
    pub fn try_acquire(&self, ip: IpAddr) -> Option<IpGuard> {
        let key = ip_key(ip);
        let mut state = self.inner.lock();
        if state.total >= self.inner.total {
            return None;
        }
        let count = state.by_ip.entry(key).or_insert(0);
        if *count >= self.inner.per_ip {
            if *count == 0 {
                state.by_ip.remove(&key);
            }
            return None;
        }
        *count += 1;
        state.total += 1;
        Some(IpGuard { inner: self.inner.clone(), key })
    }

    /// Connexions ouvertes au total.
    pub fn total(&self) -> usize {
        self.inner.lock().total
    }
}

impl Inner {
    /// Le compteur reste cohérent même si un fil a paniqué en le tenant.
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut state = self.inner.lock();
        state.total = state.total.saturating_sub(1);
        if let Some(count) = state.by_ip.get_mut(&self.key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.by_ip.remove(&self.key);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn per_ip_limit() {
        let l = IpLimiter::new(2, 10);
        let a = l.try_acquire(ip("203.0.113.1")).unwrap();
        let _b = l.try_acquire(ip("203.0.113.1")).unwrap();
        assert!(l.try_acquire(ip("203.0.113.1")).is_none());
        assert!(l.try_acquire(ip("203.0.113.2")).is_some(), "autre IP");
        drop(a);
        assert!(l.try_acquire(ip("203.0.113.1")).is_some(), "place rendue");
    }

    #[test]
    fn total_limit() {
        let l = IpLimiter::new(5, 2);
        let _a = l.try_acquire(ip("203.0.113.1")).unwrap();
        let b = l.try_acquire(ip("203.0.113.2")).unwrap();
        assert!(l.try_acquire(ip("203.0.113.3")).is_none());
        assert_eq!(l.total(), 2);
        drop(b);
        assert_eq!(l.total(), 1);
        assert!(l.try_acquire(ip("203.0.113.3")).is_some());
    }

    #[test]
    fn ipv6_counted_by_slash_64() {
        let l = IpLimiter::new(1, 10);
        let _a = l.try_acquire(ip("2001:db8:1:2::1")).unwrap();
        assert!(l.try_acquire(ip("2001:db8:1:2:ffff::9")).is_none(), "même /64");
        assert!(l.try_acquire(ip("2001:db8:1:3::1")).is_some(), "autre /64");
    }

    #[test]
    fn mapped_ipv4_is_ipv4() {
        assert_eq!(ip_key(ip("::ffff:203.0.113.1")), ip("203.0.113.1"));
        assert_eq!(ip_key(ip("2001:db8:1:2:3:4:5:6")), ip("2001:db8:1:2::"));
    }

    #[test]
    fn released_entries_do_not_accumulate() {
        let l = IpLimiter::new(1, 10);
        for i in 0..100u8 {
            drop(l.try_acquire(IpAddr::from([198, 51, 100, i])).unwrap());
        }
        assert!(l.inner.state.lock().unwrap().by_ip.is_empty());
    }
}
