//! Simple Transaction System
//! 
//! This is a simplified transaction system for multi-node testing.
//! For production, use tx_stark.rs with STARK proofs.

use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};
use anyhow::{Result, ensure};

use crate::core::Hash32;
use crate::falcon_sigs::{FalconPublicKey, FalconSecretKey, falcon_sign, falcon_verify, SignedNullifier};

/// Simple transaction (for testing)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    /// Sender's public key hash
    pub from: Hash32,
    
    /// Recipient's public key hash
    pub to: Hash32,
    
    /// Amount to transfer
    pub amount: u64,
    
    /// Transaction fee
    pub fee: u64,
    
    /// Nonce (prevents replay)
    pub nonce: u64,
    
    /// Timestamp
    pub timestamp: u64,
    
    /// Falcon signature over transaction data
    pub signature: Option<SignedNullifier>,
}

impl Transaction {
    /// Create new unsigned transaction
    pub fn new(
        from: Hash32,
        to: Hash32,
        amount: u64,
        fee: u64,
        nonce: u64,
    ) -> Self {
        Self {
            from,
            to,
            amount,
            fee,
            nonce,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            signature: None,
        }
    }
    
    /// Get transaction data for signing (without signature)
    pub fn signing_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.from);
        data.extend_from_slice(&self.to);
        data.extend_from_slice(&self.amount.to_le_bytes());
        data.extend_from_slice(&self.fee.to_le_bytes());
        data.extend_from_slice(&self.nonce.to_le_bytes());
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data
    }
    
    /// Sign transaction with Falcon secret key
    pub fn sign(&mut self, sk: &FalconSecretKey) -> Result<()> {
        let data = self.signing_data();
        let sig = falcon_sign(&data, sk)?;
        self.signature = Some(sig);
        Ok(())
    }
    
    /// Verify transaction signature
    pub fn verify(&self, pk: &FalconPublicKey) -> Result<()> {
        let sig = self.signature.as_ref().ok_or_else(|| anyhow::anyhow!("Transaction not signed"))?;
        let data = self.signing_data();
        falcon_verify(&data, sig, pk)?;
        Ok(())
    }
    
    /// Compute transaction ID
    pub fn id(&self) -> Hash32 {
        let bytes = bincode::serialize(self).expect("tx serialize");
        let mut hasher = Sha3_256::new();
        hasher.update(b"TX_ID");
        hasher.update(&bytes);
        hasher.finalize().into()
    }
    
    /// Serialize transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("tx serialize")
    }
    
    /// Deserialize transaction
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(bincode::deserialize(bytes)?)
    }
}

/// Transaction pool (mempool)
#[derive(Clone, Default)]
pub struct TxPool {
    /// Pending transactions
    transactions: std::collections::HashMap<Hash32, Transaction>,
    
    /// Nonce tracker per address
    nonces: std::collections::HashMap<Hash32, u64>,
}

impl TxPool {
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Add transaction to pool
    pub fn add(&mut self, tx: Transaction) -> Result<()> {
        let tx_id = tx.id();
        
        // Check if already in pool
        if self.transactions.contains_key(&tx_id) {
            return Ok(());
        }
        
        // Check nonce
        let expected_nonce = self.nonces.get(&tx.from).copied().unwrap_or(0);
        ensure!(tx.nonce >= expected_nonce, "Nonce too low");
        
        // Add to pool
        self.transactions.insert(tx_id, tx.clone());
        
        // Update nonce tracker
        self.nonces.insert(tx.from, tx.nonce + 1);
        
        Ok(())
    }
    
    /// Get transaction by ID
    pub fn get(&self, id: &Hash32) -> Option<&Transaction> {
        self.transactions.get(id)
    }
    
    /// Get all pending transactions
    pub fn get_all(&self) -> Vec<Transaction> {
        self.transactions.values().cloned().collect()
    }
    
    /// Remove transaction from pool
    pub fn remove(&mut self, id: &Hash32) {
        self.transactions.remove(id);
    }
    
    /// Get number of pending transactions
    pub fn len(&self) -> usize {
        self.transactions.len()
    }
    
    /// Check if pool is empty
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
    
    /// Clear all transactions
    pub fn clear(&mut self) {
        self.transactions.clear();
        self.nonces.clear();
    }
    
    /// Get transactions for block (sorted by fee, limited by count)
    pub fn get_for_block(&self, max_count: usize) -> Vec<Transaction> {
        let mut txs = self.get_all();
        txs.sort_by(|a, b| b.fee.cmp(&a.fee)); // Highest fee first
        txs.truncate(max_count);
        txs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::falcon_sigs::falcon_keypair;
    use crate::node_id::node_id_from_falcon_pk;
    
    #[test]
    fn test_transaction_sign_verify() {
        let (pk1, sk1) = falcon_keypair();
        let (pk2, _) = falcon_keypair();
        
        let from = node_id_from_falcon_pk(&pk1);
        let to = node_id_from_falcon_pk(&pk2);
        
        let mut tx = Transaction::new(from, to, 1000, 10, 0);
        tx.sign(&sk1).unwrap();
        
        assert!(tx.verify(&pk1).is_ok());
    }
    
    #[test]
    fn test_tx_pool() {
        let (pk1, sk1) = falcon_keypair();
        let (pk2, _) = falcon_keypair();
        
        let from = node_id_from_falcon_pk(&pk1);
        let to = node_id_from_falcon_pk(&pk2);
        
        let mut pool = TxPool::new();
        
        let mut tx = Transaction::new(from, to, 1000, 10, 0);
        tx.sign(&sk1).unwrap();
        
        pool.add(tx.clone()).unwrap();
        assert_eq!(pool.len(), 1);
        
        let tx_id = tx.id();
        assert!(pool.get(&tx_id).is_some());
    }
}

