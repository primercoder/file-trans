use kite_core::{
    ChunkCipher, EncryptedChunk, FileCryptoError, FileKey, decrypt_file, encrypt_file,
};
use rand::{TryRngCore as _, rngs::OsRng};

const CHUNK_SIZE: usize = 256 * 1024;

#[test]
fn round_trip_three_chunks() {
    let mut plaintext = vec![0_u8; 700 * 1024];
    OsRng.try_fill_bytes(&mut plaintext).unwrap();
    let fk = FileKey::generate().unwrap();

    let (header, chunks) = encrypt_file(&fk, plaintext.as_slice(), CHUNK_SIZE).unwrap();
    assert_eq!(header.total_chunks, 3);
    assert_eq!(header.chunk_size, CHUNK_SIZE as u32);
    assert_eq!(
        chunks
            .iter()
            .map(|chunk| chunk.ciphertext.len())
            .collect::<Vec<_>>(),
        [CHUNK_SIZE + 16, CHUNK_SIZE + 16, 188 * 1024 + 16,]
    );
    assert_eq!(decrypt_file(&fk, &header, &chunks).unwrap(), plaintext);
}

#[test]
fn out_of_order_chunks_are_buffered_and_emitted_in_order() {
    let plaintext: Vec<u8> = (0..(CHUNK_SIZE * 2 + 123)).map(|n| n as u8).collect();
    let fk = FileKey::generate().unwrap();
    let (header, chunks) = encrypt_file(&fk, plaintext.as_slice(), CHUNK_SIZE).unwrap();
    let mut cipher = ChunkCipher::new(&fk, header).unwrap();

    assert!(cipher.push_chunk(chunks[2].clone()).unwrap().is_empty());
    assert!(cipher.push_chunk(chunks[1].clone()).unwrap().is_empty());
    assert_eq!(cipher.push_chunk(chunks[0].clone()).unwrap(), plaintext);
}

#[test]
fn tampered_chunk_is_a_mac_failure() {
    let fk = FileKey::generate().unwrap();
    let (header, mut chunks) = encrypt_file(&fk, b"authenticated".as_slice(), CHUNK_SIZE).unwrap();
    chunks[0].ciphertext[3] ^= 1;

    assert!(matches!(
        decrypt_file(&fk, &header, &chunks),
        Err(FileCryptoError::MacFailure { index: 0 })
    ));
}

#[test]
fn aad_rejects_cross_file_index_transplant() {
    let fk = FileKey::generate().unwrap();
    let (_, chunks_a) =
        encrypt_file(&fk, vec![0x11; CHUNK_SIZE * 2].as_slice(), CHUNK_SIZE).unwrap();
    let (header_b, chunks_b) =
        encrypt_file(&fk, vec![0x22; CHUNK_SIZE * 2].as_slice(), CHUNK_SIZE).unwrap();
    let transplanted = EncryptedChunk {
        index: 1,
        ciphertext: chunks_a[0].ciphertext.clone(),
    };
    let chunks = vec![chunks_b[0].clone(), transplanted];

    assert!(matches!(
        decrypt_file(&fk, &header_b, &chunks),
        Err(FileCryptoError::MacFailure { index: 1 })
    ));
}

#[test]
fn wrong_chunk_count_is_a_typed_error() {
    let fk = FileKey::generate().unwrap();
    let plaintext = vec![7_u8; CHUNK_SIZE * 3];
    let (header, chunks) = encrypt_file(&fk, plaintext.as_slice(), CHUNK_SIZE).unwrap();

    assert!(matches!(
        decrypt_file(&fk, &header, &chunks[..2]),
        Err(FileCryptoError::ChunkCountMismatch {
            expected: 3,
            actual: 2
        })
    ));
}

#[test]
fn bad_header_is_rejected() {
    let fk = FileKey::generate().unwrap();
    let (mut header, chunks) = encrypt_file(&fk, b"data".as_slice(), CHUNK_SIZE).unwrap();
    header.version ^= 1;

    assert!(matches!(
        decrypt_file(&fk, &header, &chunks),
        Err(FileCryptoError::BadHeader(_))
    ));
}

#[test]
fn fixed_two_chunk_known_answer() {
    // These expected values pin the nonce/AAD derivation and ciphertext-stream hash
    // contract; they are not regenerated during the test.
    let fk = FileKey::from_bytes([0x42; 32]);
    let plaintext: Vec<u8> = (0..32).collect();
    let (header, chunks) = encrypt_file(&fk, plaintext.as_slice(), 16).unwrap();

    assert_eq!(header.total_chunks, 2);
    assert_eq!(header.chunk_size, 16);
    assert_eq!(
        hex::encode(&chunks[0].ciphertext),
        "c423d63b198678531a674bef0bfab130a84ed5f0b2a7bb1c35ec953b95fa9a3c"
    );
    assert_eq!(
        hex::encode(header.content_hash),
        "8f45be551e73770c3214e8054fe1f912c0821115f35bb2edc9e86f59e7cd2a53"
    );
}
