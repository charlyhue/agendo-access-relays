//! Lecture du nom demandé (SNI) dans le ClientHello TLS, sans rien déchiffrer.
//!
//! Le relais lit le début de la connexion du client, ici un ou plusieurs enregistrements TLS
//! `handshake` qui portent le message `ClientHello`, et en extrait l'extension `server_name`
//! (RFC 6066). Les octets lus sont ensuite rejoués tels quels vers la maison, qui fait la
//! poignée de main TLS.
//!
//! Tout est borné : message de poignée de main ≤ [`MAX_HELLO_LEN`], octets lus au total ≤
//! [`MAX_HELLO_BYTES`] (enregistrements très fragmentés compris). Aucune indexation qui puisse
//! paniquer : ce code lit des octets envoyés par n'importe qui.

/// Longueur maximale admise du message `ClientHello` (au-delà, refus).
pub const MAX_HELLO_LEN: usize = 16 * 1024;
/// Octets lus au plus pour trouver le ClientHello (en-têtes d'enregistrements compris).
pub const MAX_HELLO_BYTES: usize = MAX_HELLO_LEN + 64 * 5;
/// Longueur maximale d'un enregistrement TLS en clair (RFC 8446 §5.1).
const MAX_RECORD_LEN: usize = 1 << 14;
/// Nom d'hôte le plus long.
pub const MAX_NAME_LEN: usize = 253;

/// Refus d'un début de connexion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HelloError {
    #[error("ce n'est pas un enregistrement TLS de poignée de main")]
    NotHandshake,
    #[error("version d'enregistrement TLS inconnue")]
    Version,
    #[error("enregistrement TLS vide ou trop long")]
    Record,
    #[error("le premier message n'est pas un ClientHello")]
    NotClientHello,
    #[error("ClientHello trop long")]
    TooLong,
    #[error("ClientHello trop fragmenté")]
    TooFragmented,
    #[error("ClientHello mal formé")]
    Malformed,
    #[error("ClientHello sans nom de serveur (SNI)")]
    NoServerName,
    #[error("nom de serveur (SNI) invalide")]
    BadName,
}

/// Nom demandé, en minuscules, si `buf` contient tout le ClientHello ; `Ok(None)` s'il manque
/// des octets.
pub fn peek_sni(buf: &[u8]) -> Result<Option<String>, HelloError> {
    let Some(message) = reassemble(buf)? else {
        return if buf.len() >= MAX_HELLO_BYTES { Err(HelloError::TooFragmented) } else { Ok(None) };
    };
    server_name(message).map(Some)
}

/// Corps du message `ClientHello` (après son en-tête de 4 octets), réassemblé depuis les
/// enregistrements, ou `None` s'il manque des octets.
fn reassemble(buf: &[u8]) -> Result<Option<Vec<u8>>, HelloError> {
    let mut handshake = Vec::new();
    let mut needed: Option<usize> = None;
    let mut rest = buf;
    loop {
        if let Some(n) = needed
            && handshake.len() >= n
        {
            return Ok(handshake.get(4..n).map(<[u8]>::to_vec));
        }
        if rest.first().is_some_and(|b| *b != 0x16) {
            return Err(HelloError::NotHandshake);
        }
        let Some(&[_, major, _, hi, lo]) = rest.get(..5) else {
            return Ok(None);
        };
        if major != 3 {
            return Err(HelloError::Version);
        }
        let len = usize::from(u16::from_be_bytes([hi, lo]));
        if len == 0 || len > MAX_RECORD_LEN {
            return Err(HelloError::Record);
        }
        // Fragment complet, ou ce qui en est arrivé (pour refuser au plus tôt).
        let available = rest.len().saturating_sub(5).min(len);
        handshake.extend_from_slice(rest.get(5..5 + available).unwrap_or_default());
        if needed.is_none()
            && let Some(&[kind, a, b, c]) = handshake.get(..4)
        {
            if kind != 1 {
                return Err(HelloError::NotClientHello);
            }
            let body = usize::from(a) << 16 | usize::from(b) << 8 | usize::from(c);
            if body > MAX_HELLO_LEN {
                return Err(HelloError::TooLong);
            }
            needed = Some(4 + body);
        }
        if available < len {
            // Enregistrement incomplet : le message l'est aussi, sauf s'il tient déjà.
            return Ok(needed.filter(|n| handshake.len() >= *n).and_then(|n| handshake.get(4..n).map(<[u8]>::to_vec)));
        }
        rest = rest.get(5 + len..).unwrap_or_default();
    }
}

/// Lecture séquentielle sans panique.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], HelloError> {
        if n > self.0.len() {
            return Err(HelloError::Malformed);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, HelloError> {
        self.take(1)?.first().copied().ok_or(HelloError::Malformed)
    }

    fn u16(&mut self) -> Result<u16, HelloError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([*b.first().ok_or(HelloError::Malformed)?, *b.get(1).ok_or(HelloError::Malformed)?]))
    }

    /// Bloc préfixé par sa longueur sur un octet.
    fn vec8(&mut self) -> Result<&'a [u8], HelloError> {
        let n = self.u8()?;
        self.take(usize::from(n))
    }

    /// Bloc préfixé par sa longueur sur deux octets.
    fn vec16(&mut self) -> Result<&'a [u8], HelloError> {
        let n = self.u16()?;
        self.take(usize::from(n))
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

fn server_name(message: Vec<u8>) -> Result<String, HelloError> {
    let mut r = Reader(&message);
    r.take(2 + 32)?; // legacy_version, random
    if r.vec8()?.len() > 32 {
        return Err(HelloError::Malformed); // session_id
    }
    let suites = r.vec16()?;
    if suites.is_empty() || suites.len() % 2 != 0 {
        return Err(HelloError::Malformed);
    }
    if r.vec8()?.is_empty() {
        return Err(HelloError::Malformed); // méthodes de compression
    }
    if r.is_empty() {
        return Err(HelloError::NoServerName); // pas d'extensions du tout
    }
    let mut extensions = Reader(r.vec16()?);
    if !r.is_empty() {
        return Err(HelloError::Malformed);
    }
    let mut found = None;
    while !extensions.is_empty() {
        let kind = extensions.u16()?;
        let data = extensions.vec16()?;
        if kind != 0 {
            continue;
        }
        if found.is_some() {
            return Err(HelloError::Malformed); // extension en double (RFC 8446 §4.2)
        }
        found = Some(host_name(data)?);
    }
    found.ok_or(HelloError::NoServerName)
}

/// Premier nom `host_name` de l'extension `server_name`.
fn host_name(data: &[u8]) -> Result<String, HelloError> {
    let mut r = Reader(data);
    let mut list = Reader(r.vec16()?);
    if !r.is_empty() {
        return Err(HelloError::Malformed);
    }
    while !list.is_empty() {
        let kind = list.u8()?;
        let name = list.vec16()?;
        if kind == 0 {
            return valid_name(name);
        }
    }
    Err(HelloError::NoServerName)
}

/// Nom DNS en ASCII (`a-z`, `0-9`, `-`), étiquettes de 1 à 63 caractères, sans point final ;
/// rendu en minuscules.
fn valid_name(name: &[u8]) -> Result<String, HelloError> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(HelloError::BadName);
    }
    let lower = name.to_ascii_lowercase();
    let labels_ok = lower
        .split(|b| *b == b'.')
        .all(|label| !label.is_empty() && label.len() <= 63 && label.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-'));
    if !labels_ok {
        return Err(HelloError::BadName);
    }
    String::from_utf8(lower).map_err(|_| HelloError::BadName)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
pub(crate) mod tests {
    use std::sync::Arc;

    use super::*;

    pub(crate) const HOST: &str = "abcdefghijklmnop.maisons.exemple.fr";

    /// ClientHello réel produit par rustls pour `host`.
    pub(crate) fn rustls_client_hello(host: &str) -> Vec<u8> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(host.to_owned()).unwrap();
        let mut conn = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
        let mut out = Vec::new();
        while conn.wants_write() {
            conn.write_tls(&mut out).unwrap();
        }
        out
    }

    /// Recoupe les enregistrements `handshake` de `wire` en morceaux de `size` octets.
    fn refragment(wire: &[u8], size: usize) -> Vec<u8> {
        let mut payload = Vec::new();
        let mut rest = wire;
        while rest.len() >= 5 {
            let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
            payload.extend_from_slice(&rest[5..5 + len]);
            rest = &rest[5 + len..];
        }
        payload.chunks(size).flat_map(|c| [&[0x16, 3, 1][..], &(c.len() as u16).to_be_bytes(), c].concat()).collect()
    }

    /// ClientHello minimal écrit à la main, avec les extensions données.
    fn hello_with_extensions(extensions: &[u8]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0; 32]);
        body.push(0); // session_id
        body.extend_from_slice(&[0, 2, 0x13, 0x01]); // une suite
        body.extend_from_slice(&[1, 0]); // compression nulle
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);
        let mut hs = vec![1];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 3, 1];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    fn sni_extension(name: &[u8]) -> Vec<u8> {
        let mut entry = vec![0];
        entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
        entry.extend_from_slice(name);
        let mut list = (entry.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&entry);
        let mut ext = vec![0, 0];
        ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&list);
        ext
    }

    #[test]
    fn reads_rustls_client_hello() {
        let wire = rustls_client_hello(HOST);
        assert_eq!(peek_sni(&wire), Ok(Some(HOST.to_owned())));
    }

    #[test]
    fn waits_for_missing_bytes() {
        let wire = rustls_client_hello(HOST);
        for end in 0..wire.len() {
            assert_eq!(peek_sni(&wire[..end]), Ok(None), "{end} octets sur {}", wire.len());
        }
    }

    #[test]
    fn reassembles_fragmented_records() {
        let wire = rustls_client_hello(HOST);
        for size in [1, 7, 100, 500] {
            assert_eq!(peek_sni(&refragment(&wire, size)), Ok(Some(HOST.to_owned())), "morceaux de {size}");
        }
    }

    #[test]
    fn too_fragmented_is_refused() {
        let wire = refragment(&rustls_client_hello(HOST), 1);
        let cut = &wire[..MAX_HELLO_BYTES.min(wire.len())];
        if wire.len() > MAX_HELLO_BYTES {
            assert_eq!(peek_sni(cut), Err(HelloError::TooFragmented));
        }
        // Un ClientHello de 4 Kio en morceaux d'un octet dépasse forcément la limite.
        let big = hello_with_extensions(&[sni_extension(HOST.as_bytes()), vec![0xff, 0x01, 0x10, 0x00], vec![0; 4096]].concat());
        let wire = refragment(&big, 1);
        assert_eq!(peek_sni(&wire[..MAX_HELLO_BYTES]), Err(HelloError::TooFragmented));
    }

    #[test]
    fn normalizes_case() {
        let wire = hello_with_extensions(&sni_extension(b"ABCdefghijklmnop.Maisons.Exemple.FR"));
        assert_eq!(peek_sni(&wire), Ok(Some(HOST.to_owned())));
    }

    #[test]
    fn refuses_bad_names() {
        for name in [&b""[..], b"a b.fr", b"a..fr", b".a.fr", b"a.fr.", b"a_b.fr", b"\xc3\xa9t\xc3\xa9.fr", &[b'a'; 254]] {
            assert_eq!(peek_sni(&hello_with_extensions(&sni_extension(name))), Err(HelloError::BadName), "{name:?}");
        }
        let long_label = [&[b'a'; 64][..], b".fr"].concat();
        assert_eq!(peek_sni(&hello_with_extensions(&sni_extension(&long_label))), Err(HelloError::BadName));
    }

    #[test]
    fn refuses_missing_or_duplicate_server_name() {
        assert_eq!(peek_sni(&hello_with_extensions(&[])), Err(HelloError::NoServerName));
        let twice = [sni_extension(b"a.fr"), sni_extension(b"b.fr")].concat();
        assert_eq!(peek_sni(&hello_with_extensions(&twice)), Err(HelloError::Malformed));
    }

    #[test]
    fn refuses_other_starts() {
        assert_eq!(peek_sni(b"GET / HTTP/1.1\r\n"), Err(HelloError::NotHandshake));
        assert_eq!(peek_sni(&[0x16, 2, 0, 0, 1]), Err(HelloError::Version));
        assert_eq!(peek_sni(&[0x16, 3, 1, 0, 0]), Err(HelloError::Record), "enregistrement vide");
        assert_eq!(peek_sni(&[0x16, 3, 1, 0x40, 0x01]), Err(HelloError::Record), "enregistrement trop long");
        assert_eq!(peek_sni(&[0x16, 3, 1, 0, 4, 2, 0, 0, 0]), Err(HelloError::NotClientHello));
        assert_eq!(peek_sni(&[0x16, 3, 1, 0, 4, 1, 0x01, 0, 0]), Err(HelloError::TooLong), "65 Kio annoncés");
    }

    #[test]
    fn refuses_inconsistent_lengths() {
        let mut wire = hello_with_extensions(&sni_extension(HOST.as_bytes()));
        // Longueur de la liste des extensions faussée (+1) : le message ne se lit plus.
        let ext_len_at = 5 + 4 + 2 + 32 + 1 + 4 + 2;
        wire[ext_len_at + 1] += 1;
        assert_eq!(peek_sni(&wire), Err(HelloError::Malformed));
    }
}
