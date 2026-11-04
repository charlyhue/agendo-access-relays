//! Lecture et écriture des trames du tunnel sur un flux d'octets, bornées.

use agendo_access_protocol::frame::{Frame, FrameDecoder, FrameError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Taille des lectures successives.
const READ_CHUNK: usize = 16 * 1024;

/// Erreur de lecture ou d'écriture de trames.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("trame invalide : {0}")]
    Frame(#[from] FrameError),
    #[error("erreur d'entrée-sortie : {0}")]
    Io(#[from] std::io::Error),
}

/// Lecteur de trames : le décodeur ne garde jamais plus de `FrameDecoder::CAPACITY` octets.
#[derive(Debug, Default)]
pub struct FrameReader {
    decoder: FrameDecoder,
    chunk: Vec<u8>,
}

impl FrameReader {
    pub fn new() -> Self {
        Self { decoder: FrameDecoder::new(), chunk: vec![0; READ_CHUNK] }
    }

    /// Prochaine trame ; `Ok(None)` à la fin propre du flux (entre deux trames).
    pub async fn read<R: AsyncRead + Unpin>(&mut self, io: &mut R) -> Result<Option<Frame>, WireError> {
        loop {
            if let Some(frame) = self.decoder.next_frame()? {
                return Ok(Some(frame));
            }
            // Le décodeur n'a pas de trame complète : il reste toujours de la place, car une
            // trame tient dans la moitié de sa capacité.
            let room = self.decoder.space().min(self.chunk.len());
            let buf = self.chunk.get_mut(..room).unwrap_or_default();
            let n = io.read(buf).await?;
            if n == 0 {
                if self.decoder.buffered() == 0 {
                    return Ok(None);
                }
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
            }
            self.decoder.feed(self.chunk.get(..n).unwrap_or_default())?;
        }
    }
}

/// Écrit une trame entière.
pub async fn write_frame<W: AsyncWrite + Unpin>(io: &mut W, frame: &Frame) -> Result<(), WireError> {
    let bytes = frame.to_bytes()?;
    io.write_all(&bytes).await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reads_frames_then_clean_end() {
        let (mut a, mut b) = tokio::io::duplex(8);
        tokio::spawn(async move {
            write_frame(&mut a, &Frame::Ping { ts: 1 }).await.unwrap();
            write_frame(&mut a, &Frame::Data { stream: 3, data: vec![7; 100] }).await.unwrap();
        });
        let mut r = FrameReader::new();
        assert_eq!(r.read(&mut b).await.unwrap(), Some(Frame::Ping { ts: 1 }));
        assert_eq!(r.read(&mut b).await.unwrap(), Some(Frame::Data { stream: 3, data: vec![7; 100] }));
        assert!(r.read(&mut b).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn truncated_frame_is_an_error() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let bytes = Frame::Ping { ts: 1 }.to_bytes().unwrap();
        a.write_all(&bytes[..5]).await.unwrap();
        drop(a);
        assert!(matches!(FrameReader::new().read(&mut b).await, Err(WireError::Io(_))));
    }

    #[tokio::test]
    async fn invalid_frame_is_an_error() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&[0x99, 0, 0, 0, 0, 0, 0, 0, 0]).await.unwrap();
        assert!(matches!(FrameReader::new().read(&mut b).await, Err(WireError::Frame(FrameError::UnknownType(0x99)))));
    }
}
