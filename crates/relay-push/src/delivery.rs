//! Issue d'une remise à APNs ou FCM.

/// Réponse du service de notifications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// Acceptée.
    Sent,
    /// Jeton du téléphone périmé (APNs 410, FCM `UNREGISTERED`) : la maison l'oublie.
    Unregistered,
    /// Refusée pour cette requête (raison du service, sans donnée de la maison).
    Rejected(String),
}

/// Le service n'a pas pu traiter la requête (réseau, panne, nos identifiants) : rien n'est
/// imputable à la maison.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UpstreamError {
    #[error("service de notifications indisponible : {0}")]
    Unavailable(String),
}
