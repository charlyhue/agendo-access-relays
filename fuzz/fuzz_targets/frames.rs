//! Trames du tunnel sur des octets quelconques, tels que les reçoit le relais : décodage direct
//! et par le décodeur à tampon borné, découpé en morceaux. Jamais de panique ; une trame
//! décodée se réencode à l'identique.
#![no_main]

use agendo_access_protocol::frame::{FrameDecoder, decode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(Some((frame, used))) = decode(data) {
        assert!(used <= data.len());
        assert_eq!(frame.to_bytes().ok().as_deref(), data.get(..used));
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
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => return,
            }
        }
        assert!(decoder.buffered() <= FrameDecoder::CAPACITY);
    }
});
