//! Relais push d'**Agendo Access**.
//!
//! `POST /v1/push` : vérifie le jeton push et `Agendo-Signature`, applique les quotas du jeton,
//! remet la notification à APNs ou FCM et rend un statut synchrone. Le contenu est chiffré de
//! bout en bout entre la maison et le téléphone : le relais n'en lit rien, n'en garde rien.

pub mod apns;
pub mod delivery;
pub mod fcm;
pub mod quotas;
