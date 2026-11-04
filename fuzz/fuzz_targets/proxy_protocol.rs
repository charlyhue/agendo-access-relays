//! En-tête PROXY v2 sur des octets quelconques : jamais de panique, longueur rendue cohérente,
//! réencodage identique pour un en-tête sans TLV. Premier octet pair : la signature est
//! ajoutée devant le reste, pour que le fuzzeur explore la suite de l'en-tête.
#![no_main]

use libfuzzer_sys::fuzz_target;
use relay_sni::proxy_protocol::{MAX_HEADER_LEN, SIGNATURE, encode_v2, parse};

fuzz_target!(|data: &[u8]| {
    let input = match data.split_first() {
        Some((first, rest)) if first % 2 == 0 => [&SIGNATURE[..], rest].concat(),
        _ => data.to_vec(),
    };
    if let Ok(Some(header)) = parse(&input) {
        assert!(header.len <= input.len() && header.len <= MAX_HEADER_LEN);
        let encoded = encode_v2(header.source, header.destination);
        if encoded.len() == header.len {
            assert_eq!(parse(&encoded), Ok(Some(header)));
        }
    }
});
