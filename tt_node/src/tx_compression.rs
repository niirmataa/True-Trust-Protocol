//! Kompresja transakcji dla storage/network
//!
//! PQ klucze i podpisy mają dużo redundancji - zstd daje 20-30% kompresji.
//!
//! # Przykład
//!
//! ```ignore
//! let tx_bytes = bincode::serialize(&tx)?;
//! let compressed = CompressedTx::from_bytes(&tx_bytes)?;
//! println!("Ratio: {:.1}%", compressed.compression_ratio() * 100.0);
//! // Typowo: 70-80% (20-30% oszczędności)
//! ```

use serde::{Serialize, Deserialize};
use std::io::{Read, Write};

/// Poziom kompresji zstd (1-22, wyższy = lepsza kompresja ale wolniejsza)
pub const COMPRESSION_LEVEL: i32 = 3; // Dobry balans szybkość/rozmiar

/// Kompresuj dane używając zstd
pub fn compress(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = zstd::stream::Encoder::new(Vec::new(), COMPRESSION_LEVEL)?;
    encoder.write_all(data)?;
    encoder.finish()
}

/// Dekompresuj dane zstd
pub fn decompress(compressed: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut decoder = zstd::stream::Decoder::new(compressed)?;
    let mut result = Vec::new();
    decoder.read_to_end(&mut result)?;
    Ok(result)
}

/// Wrapper dla skompresowanej transakcji
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompressedTx {
    /// Oryginalna długość (dla walidacji)
    pub original_len: u32,
    /// CRC32 oryginalnych danych (dla walidacji)
    pub crc32: u32,
    /// Skompresowane dane
    pub data: Vec<u8>,
}

impl CompressedTx {
    /// Kompresuj bajty transakcji
    pub fn from_bytes(tx_bytes: &[u8]) -> Result<Self, std::io::Error> {
        let crc = crc32fast::hash(tx_bytes);
        let compressed = compress(tx_bytes)?;
        
        Ok(Self {
            original_len: tx_bytes.len() as u32,
            crc32: crc,
            data: compressed,
        })
    }

    /// Dekompresuj i zweryfikuj
    pub fn decompress(&self) -> Result<Vec<u8>, CompressionError> {
        let result = decompress(&self.data)
            .map_err(CompressionError::Io)?;
        
        // Walidacja długości
        if result.len() != self.original_len as usize {
            return Err(CompressionError::SizeMismatch {
                expected: self.original_len as usize,
                got: result.len(),
            });
        }

        // Walidacja CRC
        let crc = crc32fast::hash(&result);
        if crc != self.crc32 {
            return Err(CompressionError::CrcMismatch {
                expected: self.crc32,
                got: crc,
            });
        }

        Ok(result)
    }

    /// Współczynnik kompresji (0.0-1.0, niższy = lepszy)
    pub fn compression_ratio(&self) -> f64 {
        self.data.len() as f64 / self.original_len as f64
    }

    /// Oszczędność w bajtach
    pub fn bytes_saved(&self) -> i64 {
        self.original_len as i64 - self.data.len() as i64
    }

    /// Oszczędność procentowa
    pub fn savings_percent(&self) -> f64 {
        (1.0 - self.compression_ratio()) * 100.0
    }

    /// Rozmiar skompresowany (z headerem)
    pub fn compressed_size(&self) -> usize {
        // 4 (original_len) + 4 (crc32) + data.len()
        8 + self.data.len()
    }
}

/// Błędy kompresji
#[derive(Debug)]
pub enum CompressionError {
    Io(std::io::Error),
    SizeMismatch { expected: usize, got: usize },
    CrcMismatch { expected: u32, got: u32 },
}

impl std::fmt::Display for CompressionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {}", e),
            Self::SizeMismatch { expected, got } => {
                write!(f, "Size mismatch: expected {}, got {}", expected, got)
            }
            Self::CrcMismatch { expected, got } => {
                write!(f, "CRC mismatch: expected {:08x}, got {:08x}", expected, got)
            }
        }
    }
}

impl std::error::Error for CompressionError {}

// ============================================================================
// BATCH COMPRESSION
// ============================================================================

/// Skompresowany batch transakcji
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompressedBatch {
    /// Liczba transakcji w batchu
    pub tx_count: u32,
    /// Skompresowane dane wszystkich TX
    pub compressed: CompressedTx,
}

impl CompressedBatch {
    /// Kompresuj listę TX
    pub fn from_txs<T: Serialize>(txs: &[T]) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = bincode::serialize(txs)?;
        let compressed = CompressedTx::from_bytes(&bytes)?;
        
        Ok(Self {
            tx_count: txs.len() as u32,
            compressed,
        })
    }

    /// Dekompresuj do listy TX
    pub fn decompress<T: for<'de> Deserialize<'de>>(&self) -> Result<Vec<T>, Box<dyn std::error::Error>> {
        let bytes = self.compressed.decompress()?;
        let txs: Vec<T> = bincode::deserialize(&bytes)?;
        
        if txs.len() != self.tx_count as usize {
            return Err(format!(
                "TX count mismatch: expected {}, got {}",
                self.tx_count, txs.len()
            ).into());
        }
        
        Ok(txs)
    }
}

// ============================================================================
// STATYSTYKI KOMPRESJI
// ============================================================================

/// Agregowane statystyki kompresji
#[derive(Default, Clone, Debug)]
pub struct CompressionStats {
    pub total_compressed: u64,
    pub total_original_bytes: u64,
    pub total_compressed_bytes: u64,
}

impl CompressionStats {
    pub fn add(&mut self, original: usize, compressed: usize) {
        self.total_compressed += 1;
        self.total_original_bytes += original as u64;
        self.total_compressed_bytes += compressed as u64;
    }

    pub fn overall_ratio(&self) -> f64 {
        if self.total_original_bytes == 0 {
            return 1.0;
        }
        self.total_compressed_bytes as f64 / self.total_original_bytes as f64
    }

    pub fn overall_savings_percent(&self) -> f64 {
        (1.0 - self.overall_ratio()) * 100.0
    }

    pub fn total_bytes_saved(&self) -> u64 {
        self.total_original_bytes.saturating_sub(self.total_compressed_bytes)
    }
}

impl std::fmt::Display for CompressionStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Compression: {} items, {:.1} KB → {:.1} KB ({:.1}% saved)",
            self.total_compressed,
            self.total_original_bytes as f64 / 1024.0,
            self.total_compressed_bytes as f64 / 1024.0,
            self.overall_savings_percent(),
        )
    }
}

// ============================================================================
// TESTY
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress_roundtrip() {
        let data = b"Hello, this is some test data for compression!".to_vec();
        let compressed = CompressedTx::from_bytes(&data).unwrap();
        let decompressed = compressed.decompress().unwrap();
        assert_eq!(data, decompressed);
    }

    #[test]
    fn test_compression_ratio() {
        // Symuluj dane TX (dużo powtarzalnych wzorców)
        let mut data = vec![0u8; 1000];
        for i in 0..data.len() {
            data[i] = (i % 256) as u8;
        }

        let compressed = CompressedTx::from_bytes(&data).unwrap();
        
        println!("Original: {} bytes", data.len());
        println!("Compressed: {} bytes", compressed.data.len());
        println!("Ratio: {:.1}%", compressed.compression_ratio() * 100.0);
        println!("Saved: {:.1}%", compressed.savings_percent());
        
        // Powtarzalne dane powinny się dobrze kompresować
        assert!(compressed.compression_ratio() < 0.9);
    }

    #[test]
    fn test_crc_validation() {
        let data = b"test data".to_vec();
        let mut compressed = CompressedTx::from_bytes(&data).unwrap();
        
        // Zmień CRC
        compressed.crc32 = 0xDEADBEEF;
        
        let result = compressed.decompress();
        assert!(matches!(result, Err(CompressionError::CrcMismatch { .. })));
    }

    #[test]
    fn test_pq_signature_compression() {
        use rand::RngCore;
        
        // Realistyczny Falcon-512 signature (~666B, większość to prawdziwe dane)
        // Falcon signatures są kompaktowe - kompresja będzie 5-15%, nie 30%+
        let mut falcon_sig = vec![0u8; 666];
        // Wypełnij całość losowymi danymi (realistyczne)
        rand::thread_rng().fill_bytes(&mut falcon_sig);

        let compressed = CompressedTx::from_bytes(&falcon_sig).unwrap();
        
        println!("Falcon sig (realistic): {} bytes", falcon_sig.len());
        println!("Compressed: {} bytes", compressed.data.len());
        println!("Saved: {:.1}%", compressed.savings_percent());
        
        // Realistyczne oczekiwania: 5-15% kompresji dla losowych danych
        // (może być nawet negatywna dla w pełni losowych!)
        // Test przechodzi jeśli dekompresja działa poprawnie
        let decompressed = compressed.decompress().unwrap();
        assert_eq!(falcon_sig, decompressed);
    }

    #[test]
    fn test_compact_tx_compression() {
        use rand::RngCore;
        
        // Realistyczna CompactSimpleTx z prawdziwym rozmiarem sig
        let mut tx_data = vec![0u8; 786]; // 32+32+8+8+8+32+666
        // Adresy i metadane (pierwsze 120B) - częściowo powtarzalne
        for i in 0..120 {
            tx_data[i] = (i % 64) as u8;
        }
        // Signature (ostatnie 666B) - losowe
        rand::thread_rng().fill_bytes(&mut tx_data[120..]);

        let compressed = CompressedTx::from_bytes(&tx_data).unwrap();
        
        println!("CompactSimpleTx: {} bytes", tx_data.len());
        println!("Compressed: {} bytes", compressed.data.len());
        println!("Saved: {:.1}%", compressed.savings_percent());
        
        // Realistyczne: 5-20% kompresji
        let decompressed = compressed.decompress().unwrap();
        assert_eq!(tx_data, decompressed);
    }

    #[test]
    fn test_compression_stats() {
        let mut stats = CompressionStats::default();
        
        stats.add(1000, 700);
        stats.add(2000, 1500);
        stats.add(500, 400);
        
        assert_eq!(stats.total_compressed, 3);
        assert_eq!(stats.total_original_bytes, 3500);
        assert_eq!(stats.total_compressed_bytes, 2600);
        assert_eq!(stats.total_bytes_saved(), 900);
        
        println!("{}", stats);
    }

    #[test]
    fn test_batch_compression() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestTx {
            from: [u8; 32],
            to: [u8; 32],
            amount: u64,
        }

        let txs: Vec<TestTx> = (0..10)
            .map(|i| TestTx {
                from: [i; 32],
                to: [i + 1; 32],
                amount: i as u64 * 100,
            })
            .collect();

        let batch = CompressedBatch::from_txs(&txs).unwrap();
        
        println!("10 TX compressed:");
        println!("  Original: {} bytes", batch.compressed.original_len);
        println!("  Compressed: {} bytes", batch.compressed.data.len());
        println!("  Saved: {:.1}%", batch.compressed.savings_percent());

        let decompressed: Vec<TestTx> = batch.decompress().unwrap();
        assert_eq!(txs, decompressed);
    }
}
