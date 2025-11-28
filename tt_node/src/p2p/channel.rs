#![forbid(unsafe_code)]

//! Core PQ-secure P2P/RPC channel:
//! - KDF: 2 session keys from KEM shared_secret + transcript_hash,
//! - XChaCha20-Poly1305: osobny klucz dla send / recv,
//! - nonce counters (u64) per direction → brak nonce reuse.

use anyhow::{anyhow, Result};
use serde::{Serialize, Deserialize};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use zeroize::ZeroizeOnDrop;

use crate::crypto::kmac::kmac256_xof_fill;

/// 32-bajtowy hash transkryptu (np. SHA3-256).
pub type TranscriptHash = [u8; 32];

/// Symetryczny klucz sesyjny (32B) dla XChaCha20-Poly1305.
#[derive(Clone, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct SessionKey(#[zeroize] pub [u8; 32]);

impl SessionKey {
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Para kluczy dla obu kierunków (client→server, server→client).
#[derive(Clone, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct SessionKeys {
    #[zeroize]
    pub client_to_server: SessionKey,
    #[zeroize]
    pub server_to_client: SessionKey,
}

/// Wyprowadza **dwa** klucze z KEM shared_secret + transcript_hash:
///
/// - `client_to_server` – do szyfrowania ruchu **client → server**
/// - `server_to_client` – do szyfrowania ruchu **server → client**
pub fn derive_session_keys(shared_secret: &[u8], transcript_hash: &TranscriptHash) -> SessionKeys {
    let mut out = [0u8; 64];
    kmac256_xof_fill(
        shared_secret,
        b"TT-P2P-SESSION.v1",
        transcript_hash,
        &mut out,
    );

    let mut k_c2s = [0u8; 32];
    let mut k_s2c = [0u8; 32];

    k_c2s.copy_from_slice(&out[..32]);
    k_s2c.copy_from_slice(&out[32..]);

    SessionKeys {
        client_to_server: SessionKey(k_c2s),
        server_to_client: SessionKey(k_s2c),
    }
}

/// Dwukierunkowy kanał po handshaku PQ.
pub struct SecureChannel {
    aead_send: XChaCha20Poly1305,
    aead_recv: XChaCha20Poly1305,
    send_ctr: u64,
    recv_ctr: u64,
}

impl SecureChannel {
    /// Strona **serwera**:
    /// - wysyła kluczem `server_to_client`,
    /// - odbiera kluczem `client_to_server`.
    pub fn new_server(keys: &SessionKeys) -> Self {
        Self::new_internal(&keys.server_to_client, &keys.client_to_server)
    }

    /// Strona **klienta**:
    /// - wysyła kluczem `client_to_server`,
    /// - odbiera kluczem `server_to_client`.
    pub fn new_client(keys: &SessionKeys) -> Self {
        Self::new_internal(&keys.client_to_server, &keys.server_to_client)
    }

    fn new_internal(send_key: &SessionKey, recv_key: &SessionKey) -> Self {
        let aead_send = XChaCha20Poly1305::new(send_key.0.as_slice().into());
        let aead_recv = XChaCha20Poly1305::new(recv_key.0.as_slice().into());

        SecureChannel {
            aead_send,
            aead_recv,
            send_ctr: 0,
            recv_ctr: 0,
        }
    }

    #[inline]
    fn make_nonce(counter: u64) -> XNonce {
        let mut n = [0u8; 24];
        // Pierwsze 8 bajtów = licznik, reszta 0
        n[0..8].copy_from_slice(&counter.to_le_bytes());
        *XNonce::from_slice(&n)
    }

    /// Szyfrowanie wiadomości z AAD.
    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let ctr = self
            .send_ctr
            .checked_add(1)
            .ok_or_else(|| anyhow!("send nonce counter overflow"))?;
        let nonce = Self::make_nonce(self.send_ctr);
        self.send_ctr = ctr;

        let ct = self
            .aead_send
            .encrypt(&nonce, Payload { msg: plaintext, aad })
            .map_err(|e| anyhow!("encrypt failed: {e}"))?;
        Ok(ct)
    }

    /// Deszyfrowanie wiadomości z AAD.
    pub fn decrypt(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let ctr = self
            .recv_ctr
            .checked_add(1)
            .ok_or_else(|| anyhow!("recv nonce counter overflow"))?;
        let nonce = Self::make_nonce(self.recv_ctr);
        self.recv_ctr = ctr;

        let pt = self
            .aead_recv
            .decrypt(&nonce, Payload { msg: ciphertext, aad })
            .map_err(|e| anyhow!("decrypt failed: {e}"))?;
        Ok(pt)
    }

    /// Czy warto renegocjować sesję (np. po dużej liczbie ramek).
    #[inline]
    pub fn should_renegotiate(&self) -> bool {
        self.send_ctr > (1 << 32) || self.recv_ctr > (1 << 32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_two_keys_different() {
        let ss = [0x11u8; 32];
        let th = [0x22u8; 32];

        let keys = derive_session_keys(&ss, &th);

        assert_ne!(
            keys.client_to_server.as_bytes(),
            keys.server_to_client.as_bytes()
        );
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let ss = [0xAAu8; 32];
        let th = [0xBBu8; 32];
        let keys = derive_session_keys(&ss, &th);

        let mut chan_client = SecureChannel::new_client(&keys);
        let mut chan_server = SecureChannel::new_server(&keys);

        let msg = b"hello-pro-pq";
        let aad = b"test";

        let ct = chan_client.encrypt(msg, aad).unwrap();
        let pt = chan_server.decrypt(&ct, aad).unwrap();

        assert_eq!(pt, msg);
    }
}
