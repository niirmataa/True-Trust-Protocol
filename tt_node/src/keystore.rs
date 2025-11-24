//! Encrypted keystore for validator keys
//!
//! Uses XChaCha20-Poly1305 for encryption with Argon2id key derivation

use anyhow::{Context, Result, bail};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroizing;

use crate::falcon_sigs::{FalconPublicKey, FalconSecretKey};
use crate::kyber_kem::{KyberPublicKey, KyberSecretKey};

/// Encrypted keystore format (version 1)
#[derive(Serialize, Deserialize)]
pub struct EncryptedKeystore {
    /// Version for future compatibility
    pub version: u32,

    /// Argon2id salt (32 bytes)
    pub salt: [u8; 32],

    /// Argon2id parameters
    pub argon_params: ArgonParams,

    /// XChaCha20-Poly1305 nonce (24 bytes)
    pub nonce: [u8; 24],

    /// Encrypted key material (includes auth tag)
    pub ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ArgonParams {
    pub mem_cost: u32,      // Memory in KiB
    pub time_cost: u32,     // Iterations
    pub parallelism: u32,   // Threads
}

impl Default for ArgonParams {
    fn default() -> Self {
        Self {
            mem_cost: 65536,    // 64 MiB
            time_cost: 3,        // 3 iterations
            parallelism: 4,      // 4 threads
        }
    }
}

/// Decrypted validator keys
#[derive(Serialize, Deserialize, Clone)]
pub struct ValidatorKeys {
    pub falcon_pk: Vec<u8>,
    pub falcon_sk: Vec<u8>,
    pub kyber_pk: Vec<u8>,
    pub kyber_sk: Vec<u8>,
}

impl ValidatorKeys {
    /// Create from PQ keypairs
    pub fn from_keypairs(
        falcon_pk: FalconPublicKey,
        falcon_sk: FalconSecretKey,
        kyber_pk: KyberPublicKey,
        kyber_sk: KyberSecretKey,
    ) -> Self {
        use pqcrypto_traits::sign::{PublicKey as SignPk, SecretKey as SignSk};
        use pqcrypto_traits::kem::{PublicKey as KemPk, SecretKey as KemSk};

        Self {
            falcon_pk: falcon_pk.as_bytes().to_vec(),
            falcon_sk: falcon_sk.as_bytes().to_vec(),
            kyber_pk: kyber_pk.as_bytes().to_vec(),
            kyber_sk: kyber_sk.as_bytes().to_vec(),
        }
    }

    /// Convert back to typed keypairs
    pub fn to_keypairs(&self) -> Result<(FalconPublicKey, FalconSecretKey, KyberPublicKey, KyberSecretKey)> {
        let falcon_pk = crate::falcon_sigs::falcon_pk_from_bytes(&self.falcon_pk)
            .context("Invalid Falcon public key")?;
        let falcon_sk = crate::falcon_sigs::falcon_sk_from_bytes(&self.falcon_sk)
            .context("Invalid Falcon secret key")?;
        let kyber_pk = crate::kyber_kem::kyber_pk_from_bytes(&self.kyber_pk)
            .context("Invalid Kyber public key")?;
        let kyber_sk = crate::kyber_kem::kyber_sk_from_bytes(&self.kyber_sk)
            .context("Invalid Kyber secret key")?;

        Ok((falcon_pk, falcon_sk, kyber_pk, kyber_sk))
    }
}

/// Derive encryption key from password using Argon2id
fn derive_key(password: &str, salt: &[u8; 32], params: &ArgonParams) -> Result<Zeroizing<[u8; 32]>> {
    use argon2::{Argon2, Algorithm, Version, Params};

    let argon_params = Params::new(
        params.mem_cost,
        params.time_cost,
        params.parallelism,
        Some(32),
    ).map_err(|e| anyhow::anyhow!("Invalid Argon2 parameters: {}", e))?;

    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        argon_params,
    );

    let mut key = Zeroizing::new([0u8; 32]);
    argon2.hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|e| anyhow::anyhow!("Argon2 key derivation failed: {}", e))?;

    Ok(key)
}

/// Encrypt validator keys with password
pub fn encrypt_keystore(
    keys: &ValidatorKeys,
    password: &str,
    params: ArgonParams,
) -> Result<EncryptedKeystore> {
    // Generate random salt and nonce
    use rand::RngCore;
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    // Derive encryption key
    let key = derive_key(password, &salt, &params)?;

    // Serialize keys
    let plaintext = bincode::serialize(keys)
        .context("Failed to serialize keys")?;

    // Encrypt with XChaCha20-Poly1305
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let xnonce = XNonce::from_slice(&nonce);

    let ciphertext = cipher
        .encrypt(xnonce, plaintext.as_ref())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    Ok(EncryptedKeystore {
        version: 1,
        salt,
        argon_params: params,
        nonce,
        ciphertext,
    })
}

/// Decrypt validator keys with password
pub fn decrypt_keystore(
    keystore: &EncryptedKeystore,
    password: &str,
) -> Result<ValidatorKeys> {
    // Check version
    if keystore.version != 1 {
        bail!("Unsupported keystore version: {}", keystore.version);
    }

    // Derive decryption key
    let key = derive_key(password, &keystore.salt, &keystore.argon_params)?;

    // Decrypt with XChaCha20-Poly1305
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let xnonce = XNonce::from_slice(&keystore.nonce);

    let plaintext = cipher
        .decrypt(xnonce, keystore.ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("Decryption failed: invalid password or corrupted keystore"))?;

    // Deserialize keys
    let keys: ValidatorKeys = bincode::deserialize(&plaintext)
        .context("Failed to deserialize keys")?;

    Ok(keys)
}

/// Save encrypted keystore to file
pub fn save_keystore(keystore: &EncryptedKeystore, path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(keystore)
        .context("Failed to serialize keystore")?;

    std::fs::write(path, json)
        .context("Failed to write keystore file")?;

    // Set restrictive permissions (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600); // rw-------
        std::fs::set_permissions(path, perms)?;
    }

    println!("🔐 Keystore saved to: {}", path.display());
    Ok(())
}

/// Load encrypted keystore from file
pub fn load_keystore(path: &Path) -> Result<EncryptedKeystore> {
    let json = std::fs::read_to_string(path)
        .context("Failed to read keystore file")?;

    let keystore: EncryptedKeystore = serde_json::from_str(&json)
        .context("Failed to parse keystore JSON")?;

    println!("🔓 Keystore loaded from: {}", path.display());
    Ok(keystore)
}

/// Generate new validator keys and save encrypted
pub fn generate_and_save_keystore(
    path: &Path,
    password: &str,
) -> Result<ValidatorKeys> {
    println!("🔑 Generating new validator keys...");

    // Generate PQ keypairs
    let (falcon_pk, falcon_sk) = crate::falcon_sigs::falcon_keypair();
    let (kyber_pk, kyber_sk) = crate::kyber_kem::kyber_keypair();

    let keys = ValidatorKeys::from_keypairs(falcon_pk, falcon_sk, kyber_pk, kyber_sk);

    // Encrypt and save
    let keystore = encrypt_keystore(&keys, password, ArgonParams::default())?;
    save_keystore(&keystore, path)?;

    println!("✅ New validator keys generated and saved");
    Ok(keys)
}

/// Load validator keys from encrypted keystore
pub fn load_validator_keys(
    path: &Path,
    password: &str,
) -> Result<ValidatorKeys> {
    let keystore = load_keystore(path)?;
    let keys = decrypt_keystore(&keystore, password)?;
    println!("✅ Validator keys decrypted successfully");
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (falcon_pk, falcon_sk) = crate::falcon_sigs::falcon_keypair();
        let (kyber_pk, kyber_sk) = crate::kyber_kem::kyber_keypair();

        let keys = ValidatorKeys::from_keypairs(falcon_pk, falcon_sk, kyber_pk, kyber_sk);
        let password = "test_password_123";

        // Encrypt
        let keystore = encrypt_keystore(&keys, password, ArgonParams::default()).unwrap();

        // Decrypt
        let decrypted = decrypt_keystore(&keystore, password).unwrap();

        // Verify
        assert_eq!(keys.falcon_pk, decrypted.falcon_pk);
        assert_eq!(keys.falcon_sk, decrypted.falcon_sk);
        assert_eq!(keys.kyber_pk, decrypted.kyber_pk);
        assert_eq!(keys.kyber_sk, decrypted.kyber_sk);
    }

    #[test]
    fn test_wrong_password_fails() {
        let (falcon_pk, falcon_sk) = crate::falcon_sigs::falcon_keypair();
        let (kyber_pk, kyber_sk) = crate::kyber_kem::kyber_keypair();

        let keys = ValidatorKeys::from_keypairs(falcon_pk, falcon_sk, kyber_pk, kyber_sk);
        let password = "correct_password";

        let keystore = encrypt_keystore(&keys, password, ArgonParams::default()).unwrap();

        // Wrong password should fail
        let result = decrypt_keystore(&keystore, "wrong_password");
        assert!(result.is_err());
    }
}
