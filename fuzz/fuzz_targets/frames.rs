//! Trames du tunnel sur des octets quelconques, tels que les reçoit le relais : décodage direct
//! et par le décodeur à tampon borné, découpé en morceaux. Jamais de panique ; une trame
//! décodée se réencode à l'identique ; un `RENEW` décodé passe par `verify_renew` (jeton et
//! signature quelconques) sans panique.
#![no_main]

use agendo_access_protocol::{
    SigningKey,
    frame::{Frame, FrameDecoder, decode},
    keys::{TrustedKey, TrustedKeys, encode_public_key},
    token::TunnelClaims,
    tunnel::verify_renew,
};
use libfuzzer_sys::fuzz_target;

fn renew(frame: &Frame) {
    let Frame::Renew { token, signature } = frame else { return };
    let plane = SigningKey::from_bytes(&[1; 32]).verifying_key();
    let Ok(keys) = TrustedKeys::new(vec![TrustedKey { kid: "k1".into(), key: encode_public_key(&plane) }]) else { return };
    let session = TunnelClaims {
        iss: "https://api".into(),
        sub: "maison".into(),
        host: "abcdefghijklmnop.agendo.exemple.fr".into(),
        house_key: encode_public_key(&SigningKey::from_bytes(&[2; 32]).verifying_key()),
        iat: 1_793_000_000,
        exp: 1_793_086_400,
    };
    let _ = verify_renew(token, signature, &[5; 32], &session, &keys, "agendo.exemple.fr", 1_793_000_100);
}

fuzz_target!(|data: &[u8]| {
    if let Ok(Some((frame, used))) = decode(data) {
        assert!(used <= data.len());
        assert_eq!(frame.to_bytes().ok().as_deref(), data.get(..used));
        renew(&frame);
    }
    // Morceaux de taille variable, choisie par le premier octet.
    let chunk = usize::from(data.first().copied().unwrap_or(1)).max(1);
    let mut decoder = FrameDecoder::new();
    for piece in data.chunks(chunk) {
        if decoder.feed(piece).is_err() {
            return;
        }
        loop {
            match decoder.next_frame() {
                Ok(Some(frame)) => renew(&frame),
                Ok(None) => break,
                Err(_) => return,
            }
        }
        assert!(decoder.buffered() <= FrameDecoder::CAPACITY);
    }
});
