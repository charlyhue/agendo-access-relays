//! Lecture du SNI sur des octets quelconques : jamais de panique, nom rendu toujours valide,
//! résultat stable quand on ajoute des octets après un ClientHello complet.
#![no_main]

use libfuzzer_sys::fuzz_target;
use relay_sni::client_hello::{MAX_NAME_LEN, peek_sni};

fuzz_target!(|data: &[u8]| {
    if let Ok(Some(name)) = peek_sni(data) {
        assert!(!name.is_empty() && name.len() <= MAX_NAME_LEN);
        assert!(name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'));
        let mut longer = data.to_vec();
        longer.extend_from_slice(b"suite");
        assert_eq!(peek_sni(&longer), Ok(Some(name)));
    }
});
