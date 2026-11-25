//! Chunked, domain-separated AEAD encryption for file contents.

use std::{collections::BTreeMap, io::Read};

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use hkdf::Hkdf;
use rand::{TryRngCore as _, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const DOMAIN: &[u8; 12] = b"kite-file-v1";
const MAGIC: [u8; 4] = *b"KITE";
const VERSION: u8 = 1;

/// A random 256-bit key used for all chunks of one file.
#[derive(Clone, Copy)]
pub struct FileKey([u8; 32]);

impl FileKey {
    /// Generate a fresh file key from the operating system CSPRNG.
    pub fn generate() -> Self {
        let mut key = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut key)
            .expect("operating system CSPRNG failed");
        Self(key)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Metadata needed to authenticate and reassemble a ciphertext stream.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct FileHeader {
    pub magic: [u8; 4],
    pub version: u8,
    pub total_chunks: u32,
    pub chunk_size: u32,
    /// SHA-256 over every ciphertext (including its AEAD tag), in chunk order.
    pub content_hash: [u8; 32],
}

/// One independently authenticated ciphertext chunk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedChunk {
    pub index: u32,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum FileCryptoError {
    #[error("failed to read plaintext: {0}")]
    Io(#[from] std::io::Error),
    #[error("bad file header: {0}")]
    BadHeader(String),
    #[error("chunk index {index} is out of range for {total_chunks} chunks")]
    IndexOutOfRange { index: u32, total_chunks: u32 },
    #[error("duplicate chunk index {0}")]
    DuplicateIndex(u32),
    #[error("header declares {expected} chunks but received {actual}")]
    ChunkCountMismatch { expected: u32, actual: usize },
    #[error("authentication failed for chunk {index}")]
    MacFailure { index: u32 },
    #[error("ciphertext-stream content hash mismatch")]
    ContentHashMismatch,
}

/// Encrypt all bytes from `reader`, splitting at `chunk_size` bytes.
///
/// No filename or other envelope metadata is included in the header.
pub fn encrypt_file(
    fk: &FileKey,
    mut reader: impl Read,
    chunk_size: usize,
) -> Result<(FileHeader, Vec<EncryptedChunk>), FileCryptoError> {
    if chunk_size == 0 || chunk_size > u32::MAX as usize {
        return Err(FileCryptoError::BadHeader(
            "chunk_size must fit in a nonzero u32".into(),
        ));
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&fk.0));
    let mut chunks = Vec::new();
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; chunk_size];

    loop {
        let mut length = 0;
        while length < buffer.len() {
            match reader.read(&mut buffer[length..]) {
                Ok(0) => break,
                Ok(read) => length += read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        if length == 0 {
            break;
        }
        let index = u32::try_from(chunks.len()).map_err(|_| {
            FileCryptoError::BadHeader("file requires more than u32::MAX chunks".into())
        })?;
        let plaintext = buffer[..length].to_vec();
        chunks.push(PlaintextChunk { index, plaintext });
        if length < buffer.len() {
            break;
        }
    }

    let total_chunks = u32::try_from(chunks.len())
        .map_err(|_| FileCryptoError::BadHeader("too many chunks".into()))?;
    let encrypted = chunks
        .into_iter()
        .map(|chunk| {
            let aad = aad(chunk.index, total_chunks, chunk_size as u32);
            let nonce = nonce(fk, chunk.index);
            let ciphertext = cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &chunk.plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| FileCryptoError::MacFailure { index: chunk.index })?;
            hasher.update(&ciphertext);
            Ok(EncryptedChunk {
                index: chunk.index,
                ciphertext,
            })
        })
        .collect::<Result<Vec<_>, FileCryptoError>>()?;

    Ok((
        FileHeader {
            magic: MAGIC,
            version: VERSION,
            total_chunks,
            chunk_size: chunk_size as u32,
            content_hash: hasher.finalize().into(),
        },
        encrypted,
    ))
}

struct PlaintextChunk {
    index: u32,
    plaintext: Vec<u8>,
}

/// Decrypt chunks, accepting arbitrary arrival order.
pub fn decrypt_file(
    fk: &FileKey,
    header: &FileHeader,
    chunks: &[EncryptedChunk],
) -> Result<Vec<u8>, FileCryptoError> {
    if chunks.len() != header.total_chunks as usize {
        return Err(FileCryptoError::ChunkCountMismatch {
            expected: header.total_chunks,
            actual: chunks.len(),
        });
    }
    let mut cipher = ChunkCipher::new(fk, header.clone())?;
    let mut plaintext = Vec::new();
    for chunk in chunks {
        plaintext.extend(cipher.push_chunk(chunk.clone())?);
    }
    Ok(plaintext)
}

/// Stateful decryptor which buffers out-of-order chunks and emits in-order plaintext.
pub struct ChunkCipher {
    fk: FileKey,
    header: FileHeader,
    next_index: u32,
    pending: BTreeMap<u32, (Vec<u8>, Vec<u8>)>,
    hasher: Sha256,
}

impl ChunkCipher {
    pub fn new(fk: &FileKey, header: FileHeader) -> Result<Self, FileCryptoError> {
        validate_header(&header)?;
        Ok(Self {
            fk: *fk,
            header,
            next_index: 0,
            pending: BTreeMap::new(),
            hasher: Sha256::new(),
        })
    }

    /// Authenticate one chunk and return any newly contiguous plaintext.
    pub fn push_chunk(&mut self, chunk: EncryptedChunk) -> Result<Vec<u8>, FileCryptoError> {
        let index = chunk.index;
        if index >= self.header.total_chunks {
            return Err(FileCryptoError::IndexOutOfRange {
                index,
                total_chunks: self.header.total_chunks,
            });
        }
        if index < self.next_index || self.pending.contains_key(&index) {
            return Err(FileCryptoError::DuplicateIndex(index));
        }

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.fk.0));
        let nonce = nonce(&self.fk, index);
        let aad = aad(index, self.header.total_chunks, self.header.chunk_size);
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &chunk.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| FileCryptoError::MacFailure { index })?;
        self.pending.insert(index, (chunk.ciphertext, plaintext));
        let mut output = Vec::new();
        while let Some((ciphertext, plaintext)) = self.pending.remove(&self.next_index) {
            self.hasher.update(&ciphertext);
            output.extend(plaintext);
            self.next_index += 1;
        }
        if self.next_index == self.header.total_chunks
            && self.hasher.clone().finalize().as_slice() != self.header.content_hash
        {
            return Err(FileCryptoError::ContentHashMismatch);
        }
        Ok(output)
    }
}

fn validate_header(header: &FileHeader) -> Result<(), FileCryptoError> {
    if header.magic != MAGIC {
        return Err(FileCryptoError::BadHeader("invalid magic".into()));
    }
    if header.version != VERSION {
        return Err(FileCryptoError::BadHeader("unsupported version".into()));
    }
    if header.chunk_size == 0 {
        return Err(FileCryptoError::BadHeader("zero chunk size".into()));
    }
    Ok(())
}

/// Nonce = HKDF-SHA256(ikm=fk, salt="kite-file-v1" || index_be_u32,
/// info=empty), truncated to the 12-byte ChaCha20-Poly1305 nonce length.
fn nonce(fk: &FileKey, index: u32) -> [u8; 12] {
    let mut salt = [0_u8; 16];
    salt[..12].copy_from_slice(DOMAIN);
    salt[12..].copy_from_slice(&index.to_be_bytes());
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &fk.0);
    let mut nonce = [0_u8; 12];
    // A 12-byte output is always within HKDF-SHA256's length bound.
    hkdf.expand(&[], &mut nonce)
        .expect("fixed 12-byte HKDF output");
    nonce
}

/// AAD = domain || index_be_u32 || total_chunks_be_u32 || chunk_size_be_u32.
fn aad(index: u32, total_chunks: u32, chunk_size: u32) -> [u8; 24] {
    let mut aad = [0_u8; 24];
    aad[..12].copy_from_slice(DOMAIN);
    aad[12..16].copy_from_slice(&index.to_be_bytes());
    aad[16..20].copy_from_slice(&total_chunks.to_be_bytes());
    aad[20..].copy_from_slice(&chunk_size.to_be_bytes());
    aad
}
