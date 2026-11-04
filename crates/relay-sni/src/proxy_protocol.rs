//! PROXY protocol, version 2 seulement (format binaire de HAProxy).
//!
//! Traefik, en passthrough, ouvre chaque connexion vers le relais par cet en-tête : il porte
//! l'adresse réelle du client. Le relais l'**exige** et ne l'accepte que d'un amont autorisé
//! (vérifié avant la lecture, sur l'adresse du pair TCP).
//!
//! ```text
//! signature (12) | version·commande (1) | famille·transport (1) | longueur (2, big-endian) | adresses et TLV
//! ```
//!
//! Seule la commande `PROXY` sur TCP (IPv4 ou IPv6) est admise. `LOCAL` (connexion de l'amont
//! lui-même, sans client), `UNSPEC`, `UNIX` et UDP sont refusés : sans adresse de client, pas
//! de limite par IP ni d'`OPEN` correct. Les TLV éventuels sont ignorés.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use tokio::io::{AsyncRead, AsyncReadExt};

/// Signature de la version 2.
pub const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
/// Longueur de la partie fixe (signature, version, famille, longueur).
pub const FIXED_LEN: usize = 16;
/// Longueur maximale admise du bloc d'adresses et de TLV.
pub const MAX_ADDRESS_BLOCK: usize = 1024;
/// En-tête le plus long admis.
pub const MAX_HEADER_LEN: usize = FIXED_LEN + MAX_ADDRESS_BLOCK;

/// En-tête lu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyHeader {
    /// Client réel.
    pub source: SocketAddr,
    /// Adresse à laquelle le client s'est connecté (l'amont).
    pub destination: SocketAddr,
    /// Octets occupés par l'en-tête.
    pub len: usize,
}

/// Refus d'un en-tête.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProxyError {
    #[error("en-tête PROXY v2 absent (signature attendue)")]
    Signature,
    #[error("version de PROXY protocol non admise : {0}")]
    Version(u8),
    #[error("commande PROXY non admise : {0} (seule PROXY est acceptée)")]
    Command(u8),
    #[error("famille d'adresses ou transport non admis : {0:#04x}")]
    Family(u8),
    #[error("bloc d'adresses trop court pour sa famille")]
    Short,
    #[error("en-tête PROXY trop long : {0} octets annoncés")]
    TooLong(usize),
    #[error("connexion fermée avant la fin de l'en-tête PROXY")]
    Closed,
    #[error("délai dépassé pendant la lecture de l'en-tête PROXY")]
    Timeout,
    #[error("erreur de lecture de l'en-tête PROXY : {0}")]
    Io(String),
}

/// Lit un en-tête en tête de `buf` : `Ok(None)` s'il manque des octets. Une signature fausse
/// est refusée dès les premiers octets, sans attendre la suite.
pub fn parse(buf: &[u8]) -> Result<Option<ProxyHeader>, ProxyError> {
    let seen = buf.len().min(SIGNATURE.len());
    if buf.get(..seen) != SIGNATURE.get(..seen) {
        return Err(ProxyError::Signature);
    }
    let Some(&[ver_cmd, fam, len_hi, len_lo]) = buf.get(SIGNATURE.len()..FIXED_LEN) else {
        return Ok(None);
    };
    if ver_cmd >> 4 != 2 {
        return Err(ProxyError::Version(ver_cmd >> 4));
    }
    if ver_cmd & 0x0f != 1 {
        return Err(ProxyError::Command(ver_cmd & 0x0f));
    }
    let len = usize::from(u16::from_be_bytes([len_hi, len_lo]));
    if len > MAX_ADDRESS_BLOCK {
        return Err(ProxyError::TooLong(len));
    }
    // Famille et transport se vérifient avant d'attendre le bloc.
    let addr_len = match fam {
        0x11 => 12,
        0x21 => 36,
        other => return Err(ProxyError::Family(other)),
    };
    if len < addr_len {
        return Err(ProxyError::Short);
    }
    let Some(block) = buf.get(FIXED_LEN..FIXED_LEN + len) else {
        return Ok(None);
    };
    let (source, destination) = addresses(fam, block).ok_or(ProxyError::Short)?;
    Ok(Some(ProxyHeader { source, destination, len: FIXED_LEN + len }))
}

fn addresses(fam: u8, block: &[u8]) -> Option<(SocketAddr, SocketAddr)> {
    let port = |at: usize| Some(u16::from_be_bytes(block.get(at..at + 2)?.try_into().ok()?));
    if fam == 0x11 {
        let src: [u8; 4] = block.get(0..4)?.try_into().ok()?;
        let dst: [u8; 4] = block.get(4..8)?.try_into().ok()?;
        Some((
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(src)), port(8)?),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(dst)), port(10)?),
        ))
    } else {
        let src: [u8; 16] = block.get(0..16)?.try_into().ok()?;
        let dst: [u8; 16] = block.get(16..32)?.try_into().ok()?;
        Some((
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(src)), port(32)?),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(dst)), port(34)?),
        ))
    }
}

/// En-tête `PROXY` TCP de `source` vers `destination` (tests, fausse maison, amont simulé).
/// Familles différentes : l'IPv4 est écrite en IPv6 mappée.
pub fn encode_v2(source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
    let mut out = SIGNATURE.to_vec();
    out.push(0x21);
    match (source.ip(), destination.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            out.extend_from_slice(&[0x11, 0, 12]);
            out.extend_from_slice(&src.octets());
            out.extend_from_slice(&dst.octets());
        }
        (src, dst) => {
            let v6 = |ip: IpAddr| match ip {
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                IpAddr::V6(v6) => v6,
            };
            out.extend_from_slice(&[0x21, 0, 36]);
            out.extend_from_slice(&v6(src).octets());
            out.extend_from_slice(&v6(dst).octets());
        }
    }
    out.extend_from_slice(&source.port().to_be_bytes());
    out.extend_from_slice(&destination.port().to_be_bytes());
    out
}

/// Lit l'en-tête sur `stream` en moins de `timeout`, sans rien lire au-delà : la suite (le
/// ClientHello, la poignée de main du tunnel) reste à lire sur `stream`.
pub async fn read_header<R: AsyncRead + Unpin>(stream: &mut R, timeout: Duration) -> Result<ProxyHeader, ProxyError> {
    let read = async {
        let mut buf = vec![0u8; FIXED_LEN];
        read_exact(stream, &mut buf).await?;
        // La partie fixe est complète : `parse` dit la longueur du bloc ou refuse.
        if let Some(header) = parse(&buf)? {
            return Ok(header);
        }
        let block = buf.get(FIXED_LEN - 2..FIXED_LEN).and_then(|b| b.try_into().ok()).map(u16::from_be_bytes).unwrap_or(0);
        buf.resize(FIXED_LEN + usize::from(block), 0);
        read_exact(stream, buf.get_mut(FIXED_LEN..).unwrap_or_default()).await?;
        parse(&buf)?.ok_or(ProxyError::Short)
    };
    tokio::time::timeout(timeout, read).await.map_err(|_| ProxyError::Timeout)?
}

async fn read_exact<R: AsyncRead + Unpin>(stream: &mut R, buf: &mut [u8]) -> Result<(), ProxyError> {
    match stream.read_exact(buf).await {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(ProxyError::Closed),
        Err(e) => Err(ProxyError::Io(e.kind().to_string())),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn raw(ver_cmd: u8, fam: u8, block: &[u8]) -> Vec<u8> {
        let mut b = SIGNATURE.to_vec();
        b.push(ver_cmd);
        b.push(fam);
        b.extend_from_slice(&(block.len() as u16).to_be_bytes());
        b.extend_from_slice(block);
        b
    }

    #[test]
    fn ipv4_exact_layout() {
        let bytes = encode_v2(addr("203.0.113.7:51000"), addr("10.0.1.5:8443"));
        let mut block = vec![203, 0, 113, 7, 10, 0, 1, 5];
        block.extend_from_slice(&51000u16.to_be_bytes());
        block.extend_from_slice(&8443u16.to_be_bytes());
        assert_eq!(bytes, raw(0x21, 0x11, &block));
        let header = parse(&bytes).unwrap().unwrap();
        assert_eq!(header, ProxyHeader { source: addr("203.0.113.7:51000"), destination: addr("10.0.1.5:8443"), len: 28 });
    }

    #[test]
    fn ipv6_round_trip() {
        let bytes = encode_v2(addr("[2001:db8::7]:443"), addr("[2001:db8::1]:8443"));
        assert_eq!(bytes.len(), 16 + 36);
        assert_eq!(parse(&bytes).unwrap().unwrap().source, addr("[2001:db8::7]:443"));
    }

    #[test]
    fn mixed_families_use_mapped_ipv6() {
        let bytes = encode_v2(addr("203.0.113.7:1"), addr("[2001:db8::1]:2"));
        assert_eq!(bytes[13], 0x21);
        assert_eq!(parse(&bytes).unwrap().unwrap().source, addr("[::ffff:203.0.113.7]:1"));
    }

    #[test]
    fn tlvs_are_skipped_and_surplus_is_left() {
        let mut block = vec![203, 0, 113, 7, 10, 0, 1, 5, 0, 1, 0, 2];
        block.extend_from_slice(&[0x04, 0, 2, 0xaa, 0xbb]); // TLV NOOP
        let mut bytes = raw(0x21, 0x11, &block);
        let len = bytes.len();
        bytes.extend_from_slice(b"\x16\x03\x01");
        let header = parse(&bytes).unwrap().unwrap();
        assert_eq!(header.len, len);
        assert_eq!(header.source, addr("203.0.113.7:1"));
    }

    #[test]
    fn truncated_input_waits() {
        let bytes = encode_v2(addr("[2001:db8::7]:443"), addr("[2001:db8::1]:8443"));
        for end in 0..bytes.len() {
            assert_eq!(parse(&bytes[..end]), Ok(None), "{end} octets");
        }
    }

    #[test]
    fn wrong_signature_refused_from_first_bytes() {
        assert_eq!(parse(b"\x16\x03"), Err(ProxyError::Signature), "ClientHello direct");
        assert_eq!(parse(b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n"), Err(ProxyError::Signature), "version 1 texte");
        assert_eq!(parse(b"\r\n\r\n\0\r\nQUIX\n"), Err(ProxyError::Signature));
    }

    #[test]
    fn refused_versions_commands_and_families() {
        let v4 = [203, 0, 113, 7, 10, 0, 1, 5, 0, 1, 0, 2];
        assert_eq!(parse(&raw(0x11, 0x11, &v4)), Err(ProxyError::Version(1)));
        assert_eq!(parse(&raw(0x20, 0x11, &v4)), Err(ProxyError::Command(0)), "LOCAL");
        assert_eq!(parse(&raw(0x22, 0x11, &v4)), Err(ProxyError::Command(2)));
        assert_eq!(parse(&raw(0x21, 0x00, &v4)), Err(ProxyError::Family(0x00)), "UNSPEC");
        assert_eq!(parse(&raw(0x21, 0x12, &v4)), Err(ProxyError::Family(0x12)), "UDP");
        assert_eq!(parse(&raw(0x21, 0x31, &[0; 216])), Err(ProxyError::Family(0x31)), "UNIX");
        assert_eq!(parse(&raw(0x21, 0x21, &v4)), Err(ProxyError::Short), "IPv6 trop court");
    }

    #[test]
    fn oversized_block_refused_from_fixed_part() {
        let mut b = SIGNATURE.to_vec();
        b.extend_from_slice(&[0x21, 0x11]);
        b.extend_from_slice(&((MAX_ADDRESS_BLOCK + 1) as u16).to_be_bytes());
        assert_eq!(parse(&b), Err(ProxyError::TooLong(MAX_ADDRESS_BLOCK + 1)));
    }

    #[tokio::test]
    async fn read_header_leaves_the_rest_unread() {
        let mut wire = encode_v2(addr("203.0.113.7:51000"), addr("10.0.1.5:8443"));
        wire.extend_from_slice(b"suite");
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            for byte in wire {
                a.write_all(&[byte]).await.unwrap();
            }
            // Garder la connexion ouverte : le lecteur ne doit pas attendre la fin.
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let header = read_header(&mut b, Duration::from_secs(2)).await.unwrap();
        assert_eq!(header.source, addr("203.0.113.7:51000"));
        let mut rest = [0u8; 5];
        b.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"suite");
    }

    #[tokio::test]
    async fn read_header_times_out_and_detects_close() {
        let (_a, mut b) = tokio::io::duplex(64);
        assert_eq!(read_header(&mut b, Duration::from_millis(50)).await, Err(ProxyError::Timeout));
        let (a, mut b) = tokio::io::duplex(64);
        drop(a);
        assert_eq!(read_header(&mut b, Duration::from_secs(1)).await, Err(ProxyError::Closed));
    }
}
