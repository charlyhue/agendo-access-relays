//! Ce que lit le relais push avant tout envoi : corps JSON, validation, en-tête
//! `Agendo-Signature` et jeton push. Jamais de panique.
#![no_main]

use agendo_access_protocol::{
    SigningKey,
    keys::{TrustedKey, TrustedKeys, encode_public_key},
    push::PushRequest,
    signature::verify_request,
    token::PushClaims,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = serde_json::from_slice::<PushRequest>(data) {
        let _ = request.validate();
    }
    let text = String::from_utf8_lossy(data);
    let key = SigningKey::from_bytes(&[2; 32]).verifying_key();
    let _ = verify_request(&text, "POST", "/v1/push", data, 1_793_000_000, &key);
    let trusted = TrustedKeys::new(vec![TrustedKey { kid: "k1".into(), key: encode_public_key(&key) }]);
    if let Ok(trusted) = trusted {
        let _ = PushClaims::verify(&text, &trusted, 1_793_000_000);
    }
});
