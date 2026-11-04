//! En-tête PROXY v2 sur des octets quelconques : jamais de panique, longueur rendue cohérente,
//! réencodage identique pour un en-tête sans TLV.
#![no_main]

use libfuzzer_sys::fuzz_target;
use relay_sni::proxy_protocol::{MAX_HEADER_LEN, encode_v2, parse};

fuzz_target!(|data: &[u8]| {
    if let Ok(Some(header)) = parse(data) {
        assert!(header.len <= data.len() && header.len <= MAX_HEADER_LEN);
        let encoded = encode_v2(header.source, header.destination);
        if encoded.len() == header.len {
            assert_eq!(parse(&encoded), Ok(Some(header)));
        }
    }
});
