//! Maisons connectées, par nom d'hôte servi. Un nom est servi par **une** connexion à la fois :
//! la plus récente gagne, l'ancienne reçoit `GOAWAY` 1.

use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard, PoisonError},
};

use crate::tunnel::TunnelHandle;

#[derive(Debug, Default)]
pub struct Registry {
    tunnels: Mutex<HashMap<String, TunnelHandle>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, TunnelHandle>> {
        self.tunnels.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Inscrit `handle` pour son nom d'hôte ; rend le tunnel remplacé, s'il y en avait un.
    pub fn register(&self, handle: TunnelHandle) -> Option<TunnelHandle> {
        self.lock().insert(handle.host().to_owned(), handle)
    }

    /// Tunnel qui sert `host`.
    pub fn get(&self, host: &str) -> Option<TunnelHandle> {
        self.lock().get(host).cloned()
    }

    /// Retire `host`, seulement s'il est encore servi par le tunnel `id` (un tunnel remplacé ne
    /// désinscrit pas son successeur en se fermant).
    pub fn unregister(&self, host: &str, id: u64) {
        let mut tunnels = self.lock();
        if tunnels.get(host).is_some_and(|t| t.id() == id) {
            tunnels.remove(host);
        }
    }

    /// Tous les tunnels (arrêt du relais).
    pub fn all(&self) -> Vec<TunnelHandle> {
        self.lock().values().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }
}
