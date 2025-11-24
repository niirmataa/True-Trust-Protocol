#![forbid(unsafe_code)]

//! PQ-secure handshake dla P2P / RPC:
//! - tożsamość: Falcon-512 + Kyber-768 (NodeId = fingerprint PQC),
//! - handshake: ClientHello / ServerHello / ClientFinished,
//! - KEM: Kyber → shared_secret,
//! - KDF: KMAC256-XOF(shared_secret, transcript_hash) → SessionKeys,
//! - podpisy: Falcon nad transkryptem (ServerHello + ClientFinished).

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256, Sha3_512};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use pqcrypto_traits::kem::PublicKey as PQKemPublicKey;

use crate::falcon_sigs::{
    compute_pqc_fingerprint, falcon_keypair, falcon_pk_from_bytes, falcon_pk_to_bytes,
    falcon_sign, falcon_verify, FalconPublicKey, FalconSecretKey,
    SignedNullifier as FalconSignature,
};
use crate::kyber_kem::{
    kyber_ct_from_bytes, kyber_ct_to_bytes, kyber_decapsulate, kyber_encapsulate, kyber_keypair,
    kyber_pk_from_bytes, kyber_pk_to_bytes, kyber_ss_to_bytes, KyberPublicKey, KyberSecretKey,
    KyberSharedSecret,
};
use crate::node_id::NodeId;
use crate::p2p::channel::{derive_session_keys, SessionKeys, TranscriptHash};

pub const PROTOCOL_VERSION: u32 = 1;
const MAX_CLOCK_SKEW_SECS: i64 = 60;

/// Tożsamość węzła (długoterminowa, PQC).
#[derive(Clone)]
pub struct SecureNodeIdentity {
    pub node_id: NodeId,
    pub falcon_pk: FalconPublicKey,
    falcon_sk: FalconSecretKey,
    pub kyber_pk: KyberPublicKey,
    kyber_sk: KyberSecretKey,
}

/// Alias używany wszędzie.
pub type NodeIdentity = SecureNodeIdentity;

impl SecureNodeIdentity {
    pub fn from_keys(
        falcon_pk: FalconPublicKey,
        falcon_sk: FalconSecretKey,
        kyber_pk: KyberPublicKey,
        kyber_sk: KyberSecretKey,
    ) -> Self {
        let node_id = compute_pqc_fingerprint(&falcon_pk, kyber_pk.as_bytes());
        SecureNodeIdentity {
            node_id,
            falcon_pk,
            falcon_sk,
            kyber_pk,
            kyber_sk,
        }
    }

    /// Generuje świeżą tożsamość (OS RNG).
    pub fn generate() -> Self {
        let (falcon_pk, falcon_sk) = falcon_keypair();
        let (kyber_pk, kyber_sk) = kyber_keypair();
        Self::from_keys(falcon_pk, falcon_sk, kyber_pk, kyber_sk)
    }
}

/* ======================= Transcript ===================== */

/// Hasher transkryptu:
/// - wewnątrz SHA3-512 po domain-separated danych,
/// - do podpisu używamy SHA3-512,
/// - do KDF używamy SHA3-256(SHA3-512(...)) → TranscriptHash.
#[derive(Clone)]
pub struct TranscriptHasher {
    hasher: Sha3_512,
}

impl TranscriptHasher {
    pub fn new() -> Self {
        let mut h = Sha3_512::new();
        h.update(b"TT-P2P-TRANSCRIPT.v1");
        TranscriptHasher { hasher: h }
    }

    pub fn update(&mut self, domain: &[u8], data: &[u8]) {
        self.hasher
            .update(&(domain.len() as u64).to_le_bytes());
        self.hasher.update(domain);
        self.hasher
            .update(&(data.len() as u64).to_le_bytes());
        self.hasher.update(data);
    }

    /// 512-bit do podpisu Falconem.
    pub fn finalize_for_signing(&self) -> Vec<u8> {
        self.hasher.clone().finalize().to_vec()
    }

    /// 256-bit do KDF (klucze sesyjne).
    pub fn finalize_for_kdf(&self) -> TranscriptHash {
        let inner = self.hasher.clone().finalize();
        let mut h = Sha3_256::new();
        h.update(&inner);
        let digest = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
}

/* ======================= Messages ===================== */

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientHello {
    pub node_id: NodeId,
    pub falcon_pk: Vec<u8>,
    pub kyber_pk: Vec<u8>,
    pub protocol_version: u32,
    pub timestamp: u64,           // sekundy od UNIX_EPOCH
    pub anti_replay_nonce: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ServerHelloUnsigned {
    pub node_id: NodeId,
    pub falcon_pk: Vec<u8>,
    pub kyber_ct: Vec<u8>,
    pub protocol_version: u32,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerHello {
    pub node_id: NodeId,
    pub falcon_pk: Vec<u8>,
    pub kyber_ct: Vec<u8>,
    pub protocol_version: u32,
    pub timestamp: u64,
    pub falcon_signature: FalconSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientFinished {
    pub sig: FalconSignature,
}

/* ======================= Helpers ===================== */

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

fn validate_timestamp(ts: u64) -> Result<()> {
    let now = now_secs() as i64;
    let ts_i = ts as i64;
    if (now - ts_i).abs() > MAX_CLOCK_SKEW_SECS {
        return Err(anyhow!("timestamp too far from local clock"));
    }
    Ok(())
}

/* ======================= Handshake API ===================== */

/// Klient: buduje ClientHello + świeży transkrypt.
/// Uwaga: tutaj **nie** aktualizujemy transkryptu; obie strony robią
/// `CLIENT_HELLO` wewnątrz `handle_client_hello` / `handle_server_hello`
/// żeby transkrypt był identyczny.
pub fn build_client_hello(
    id: &NodeIdentity,
    protocol_version: u32,
) -> Result<(ClientHello, TranscriptHasher)> {
    let ch = ClientHello {
        node_id: id.node_id,
        falcon_pk: falcon_pk_to_bytes(&id.falcon_pk).to_vec(),
        kyber_pk: kyber_pk_to_bytes(&id.kyber_pk).to_vec(),
        protocol_version,
        timestamp: now_secs(),
        anti_replay_nonce: {
            use rand::RngCore;
            let mut n = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut n);
            n
        },
    };

    let transcript = TranscriptHasher::new();
    Ok((ch, transcript))
}

/// Serwer: obsługuje ClientHello, tworzy ServerHello + liczy klucze sesyjne.
pub fn handle_client_hello(
    server_id: &NodeIdentity,
    ch: &ClientHello,
    expected_version: u32,
    mut transcript: TranscriptHasher,
) -> Result<(ServerHello, SessionKeys, TranscriptHasher)> {
    if ch.protocol_version != expected_version {
        return Err(anyhow!(
            "protocol version mismatch: client={}, expected={}",
            ch.protocol_version,
            expected_version
        ));
    }
    validate_timestamp(ch.timestamp)?;

    // Klucze klienta
    let _client_falcon_pk =
        falcon_pk_from_bytes(&ch.falcon_pk).context("invalid client Falcon pk")?;
    let client_kyber_pk =
        kyber_pk_from_bytes(&ch.kyber_pk).context("invalid client Kyber pk")?;

    // Transkrypt: CLIENT_HELLO
    let ch_bytes = bincode::serialize(ch)?;
    transcript.update(b"CLIENT_HELLO", &ch_bytes);

    // Kyber KEM → shared_secret + ciphertext
    let (ss, ct): (KyberSharedSecret, _) = kyber_encapsulate(&client_kyber_pk);
    let ct_bytes = kyber_ct_to_bytes(&ct).to_vec();

    // unsigned ServerHello
    let sh_unsigned = ServerHelloUnsigned {
        node_id: server_id.node_id,
        falcon_pk: falcon_pk_to_bytes(&server_id.falcon_pk).to_vec(),
        kyber_ct: ct_bytes.clone(),
        protocol_version: expected_version,
        timestamp: now_secs(),
    };

    let sh_unsigned_bytes = bincode::serialize(&sh_unsigned)?;
    transcript.update(b"SERVER_HELLO", &sh_unsigned_bytes);

    // podpis Falconem nad transkryptem
    let to_sign = transcript.finalize_for_signing();
    let sig = falcon_sign(&to_sign, &server_id.falcon_sk)
        .context("Falcon sign(ServerHello) failed")?;

    let sh = ServerHello {
        node_id: sh_unsigned.node_id,
        falcon_pk: sh_unsigned.falcon_pk,
        kyber_ct: sh_unsigned.kyber_ct,
        protocol_version: sh_unsigned.protocol_version,
        timestamp: sh_unsigned.timestamp,
        falcon_signature: sig,
    };

    // KDF kluczy sesyjnych
    let ss_bytes = kyber_ss_to_bytes(&ss);
    let thash = transcript.finalize_for_kdf();
    let session_keys = derive_session_keys(ss_bytes.as_ref(), &thash);

    Ok((sh, session_keys, transcript))
}

/// Klient: weryfikuje ServerHello i liczy te same klucze sesyjne.
pub fn handle_server_hello(
    client_id: &NodeIdentity,
    ch: &ClientHello,
    sh: &ServerHello,
    mut transcript: TranscriptHasher,
    expected_version: u32,
) -> Result<(SessionKeys, TranscriptHasher)> {
    if sh.protocol_version != expected_version {
        return Err(anyhow!(
            "protocol version mismatch: server={}, expected={}",
            sh.protocol_version,
            expected_version
        ));
    }
    validate_timestamp(sh.timestamp)?;

    // CLIENT_HELLO
    let ch_bytes = bincode::serialize(ch)?;
    transcript.update(b"CLIENT_HELLO", &ch_bytes);

    // unsigned ServerHello (bez podpisu)
    let sh_unsigned = ServerHelloUnsigned {
        node_id: sh.node_id,
        falcon_pk: sh.falcon_pk.clone(),
        kyber_ct: sh.kyber_ct.clone(),
        protocol_version: sh.protocol_version,
        timestamp: sh.timestamp,
    };
    let sh_unsigned_bytes = bincode::serialize(&sh_unsigned)?;
    transcript.update(b"SERVER_HELLO", &sh_unsigned_bytes);

    // Weryfikacja podpisu serwera
    let server_falcon_pk =
        falcon_pk_from_bytes(&sh.falcon_pk).context("invalid server Falcon pk")?;
    let to_verify = transcript.finalize_for_signing();
    falcon_verify(&to_verify, &sh.falcon_signature, &server_falcon_pk)
        .context("ServerHello Falcon signature invalid")?;

    // Kyber decapsulate po stronie klienta
    let ct = kyber_ct_from_bytes(&sh.kyber_ct).context("invalid Kyber ciphertext")?;
    let ss = kyber_decapsulate(&ct, &client_id.kyber_sk)
        .context("Kyber decapsulate failed")?;
    let ss_bytes = kyber_ss_to_bytes(&ss);
    let thash = transcript.finalize_for_kdf();
    let session_keys = derive_session_keys(ss_bytes.as_ref(), &thash);

    Ok((session_keys, transcript))
}

/// Klient: ClientFinished = podpis transkryptu (po SH) swoim Falconem.
pub fn build_client_finished(
    client_id: &NodeIdentity,
    mut transcript: TranscriptHasher,
) -> Result<(ClientFinished, TranscriptHasher)> {
    transcript.update(b"CLIENT_FINISHED", &[]);
    let to_sign = transcript.finalize_for_signing();
    let sig = falcon_sign(&to_sign, &client_id.falcon_sk)
        .context("Falcon sign(ClientFinished) failed")?;
    Ok((ClientFinished { sig }, transcript))
}

/// Serwer: weryfikuje ClientFinished używając Falcon pk z ClientHello.
pub fn verify_client_finished(
    client_falcon_pk_bytes: &[u8],
    mut transcript: TranscriptHasher,
    cf: &ClientFinished,
) -> Result<TranscriptHasher> {
    let client_falcon_pk =
        falcon_pk_from_bytes(client_falcon_pk_bytes).context("invalid client Falcon pk")?;
    transcript.update(b"CLIENT_FINISHED", &[]);
    let to_verify = transcript.finalize_for_signing();
    falcon_verify(&to_verify, &cf.sig, &client_falcon_pk)
        .context("ClientFinished signature invalid")?;
    Ok(transcript)
}
