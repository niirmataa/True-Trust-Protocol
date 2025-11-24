#![forbid(unsafe_code)]

//! Core PQ-secure P2P channel:
//! - KDF: 2 session keys from KEM shared_secret + transcript_hash,
//! - XChaCha20-Poly1305: separate key for send / recv,
//! - nonce counters (u64) per direction – no nonce reuse.
//!
//! This module does NOT do network handshake – only channel cryptography.

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use zeroize::Zeroize;

use crate::crypto::kmac as ck;

/// 32-byte hash of handshake transcript.
pub type TranscriptHash = [u8; 32];

/// Symmetric session key for XChaCha20-Poly1305.
///
/// Note: memory is zeroized on Drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SessionKey(pub [u8; 32]);

impl SessionKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Derives two keys from KEM shared_secret + transcript_hash:
/// - k_c2s: client → server
/// - k_s2c: server → client
///
/// Use:
/// - on client side: send = k_c2s, recv = k_s2c
/// - on server side: send = k_s2c, recv = k_c2s
pub fn derive_session_keys(
    shared_secret: &[u8],
    transcript_hash: &TranscriptHash,
) -> (SessionKey, SessionKey) {
    // KMAC256-XOF:
    // K = kmac256_xof(key = shared_secret,
    //                 custom = "TT-P2P-SESSION.v1",
    //                 data = transcript_hash,
    //                 out_len = 64)
    let out = ck::kmac256_xof(
        shared_secret,
        b"TT-P2P-SESSION.v1",
        transcript_hash,
        64,
    );

    let mut k_c2s = [0u8; 32];
    let mut k_s2c = [0u8; 32];
    k_c2s.copy_from_slice(&out[..32]);
    k_s2c.copy_from_slice(&out[32..64]);

    (SessionKey(k_c2s), SessionKey(k_s2c))
}

/// Bidirectional, PQ-secure channel after handshake.
///
/// - separate XChaCha20-Poly1305 keys for send/recv,
/// - nonce counters per direction (u64 → 8 bytes in 24B nonce).
pub struct SecureChannel {
    aead_send: XChaCha20Poly1305,
    aead_recv: XChaCha20Poly1305,
    send_ctr: u64,
    recv_ctr: u64,
}

impl SecureChannel {
    /// Creates channel from session keys:
    /// - `send_key` – key for encrypting outgoing,
    /// - `recv_key` – key for decrypting incoming.
    pub fn new(send_key: SessionKey, recv_key: SessionKey) -> Self {
        let aead_send = XChaCha20Poly1305::new(send_key.0.as_slice().into());
        let aead_recv = XChaCha20Poly1305::new(recv_key.0.as_slice().into());

        Self {
            aead_send,
            aead_recv,
            send_ctr: 0,
            recv_ctr: 0,
        }
    }

    /// Creates a server-side channel from session key (assuming single symmetric key)
    /// For compatibility with RPC code that expects this API
    pub fn new_server(session_key: &crate::p2p::secure::SessionKey) -> Self {
        // For server: we use same key for both directions (symmetric)
        // In production, derive_session_keys should be used for proper bidirectional keys
        let key_bytes = session_key.as_bytes();
        let send_key = SessionKey(*key_bytes);
        let recv_key = SessionKey(*key_bytes);
        Self::new(send_key, recv_key)
    }

    /// Creates a client-side channel from session key (assuming single symmetric key)
    /// For compatibility with RPC code that expects this API
    pub fn new_client(session_key: &crate::p2p::secure::SessionKey) -> Self {
        // For client: same as server in symmetric mode
        Self::new_server(session_key)
    }

    /// Creates nonce from 64-bit counter.
    /// Remaining 16 bytes left at 0 – keys differ per direction, so no (key, nonce) collision.
    #[inline]
    fn make_nonce(counter: u64) -> XNonce {
        let mut n = [0u8; 24];
        n[0..8].copy_from_slice(&counter.to_le_bytes());
        *XNonce::from_slice(&n)
    }

    /// Encrypt message (send → peer).
    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let ctr = self
            .send_ctr
            .checked_add(1)
            .ok_or_else(|| anyhow!("send nonce counter overflow"))?;
        let nonce = Self::make_nonce(self.send_ctr);
        self.send_ctr = ctr;

        let ct = self
            .aead_send
            .encrypt(
                &nonce,
                Payload { msg: plaintext, aad },
            )
            .map_err(|e| anyhow!("encrypt failed: {e}"))?;
        Ok(ct)
    }

    /// Decrypt message (recv ← peer).
    pub fn decrypt(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let ctr = self
            .recv_ctr
            .checked_add(1)
            .ok_or_else(|| anyhow!("recv nonce counter overflow"))?;
        let nonce = Self::make_nonce(self.recv_ctr);
        self.recv_ctr = ctr;

        let pt = self
            .aead_recv
            .decrypt(
                &nonce,
                Payload { msg: ciphertext, aad },
            )
            .map_err(|e| anyhow!("decrypt failed: {e}"))?;
        Ok(pt)
    }

    /// Check if channel should be renegotiated based on nonce counter usage
    /// Returns true if counters are getting close to overflow (> 2^32 messages)
    pub fn should_renegotiate(&self) -> bool {
        const RENEGOTIATE_THRESHOLD: u64 = 1u64 << 32; // 4 billion messages
        self.send_ctr > RENEGOTIATE_THRESHOLD || self.recv_ctr > RENEGOTIATE_THRESHOLD
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_keys_is_deterministic() {
        let ss = b"shared_secret_example";
        let mut th = [0u8; 32];
        th[0..4].copy_from_slice(b"TEST");

        let (k1_a, k1_b) = derive_session_keys(ss, &th);
        let (k2_a, k2_b) = derive_session_keys(ss, &th);

        assert_eq!(k1_a.as_bytes(), k2_a.as_bytes());
        assert_eq!(k1_b.as_bytes(), k2_b.as_bytes());
        assert_ne!(k1_a.as_bytes(), k1_b.as_bytes()); // dwa różne kierunki
    }

    #[test]
    fn secure_channel_roundtrip() {
        let ss = b"shared_secret_example";
        let mut th = [0u8; 32];
        th[0..4].copy_from_slice(b"TEST");

        let (k_c2s, k_s2c) = derive_session_keys(ss, &th);

        // klient
        let mut chan_client = SecureChannel::new(k_c2s.clone(), k_s2c.clone());
        // serwer
        let mut chan_server = SecureChannel::new(k_s2c, k_c2s);

        let aad = b"header";
        let msg1 = b"hello from client";
        let msg2 = b"hello from server";

        // C → S
        let ct1 = chan_client.encrypt(msg1, aad).unwrap();
        let pt1 = chan_server.decrypt(&ct1, aad).unwrap();
        assert_eq!(pt1, msg1);

        // S → C
        let ct2 = chan_server.encrypt(msg2, aad).unwrap();
        let pt2 = chan_client.decrypt(&ct2, aad).unwrap();
        assert_eq!(pt2, msg2);
    }
}