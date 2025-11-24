#![forbid(unsafe_code)]

//! Thin, safe wrapper around the `randomx-rs` crate.
//!
//! - pod spodem leci oficjalny C/C++ RandomX (tevador/RandomX)
//! - my tylko konfigurujemy flagi i wystawiamy proste API:
//!   * RandomXConfig – konfiguracja VM
//!   * RandomXEngine – trzyma VM + cache (+ opcjonalnie dataset)
//!   * RandomXEngine::hash() – liczenie pojedynczego hasha
//!   * mine() – prosta pętla PoW (demo / testy)

use randomx_rs::{RandomXCache, RandomXDataset, RandomXError, RandomXFlag, RandomXVM};

/// Konfiguracja VM – tylko rzeczy, które faktycznie mają znaczenie
/// z punktu widzenia platformy.
#[derive(Debug, Clone, Copy)]
pub struct RandomXConfig {
    /// Czy próbujemy używać huge / large pages.
    pub use_large_pages: bool,
    /// Czy wymuszamy "secure JIT" (RW != RX jednocześnie).
    pub secure_jit: bool,
    /// Czy używamy FULL_MEM (pełne 2 GiB dataset w VM).
    ///
    /// - true  => tryb "fast miner" (2 GiB pamięci, szybkie hashe)
    /// - false => tryb "light" (256 MiB cache, wolne, ale tanie)
    pub full_mem: bool,
}

impl Default for RandomXConfig {
    fn default() -> Self {
        Self {
            use_large_pages: false,
            secure_jit: false,
            full_mem: true, // domyślnie pełny dataset = szybkie kopanie
        }
    }
}

/// Główny wrapper na RandomX:
/// trzyma VM, cache i opcjonalnie dataset.
#[derive(Debug)]
pub struct RandomXEngine {
    vm: RandomXVM,
    cache: RandomXCache,
    dataset: Option<RandomXDataset>,
    flags_vm: RandomXFlag,
}

impl RandomXEngine {
    /// Tworzy pełny VM z 2 GiB datasetem (szybkie kopanie).
    ///
    /// `key` to Twój klucz epokowy / seed (np. 32 bajty z KMAC).
    pub fn new_fast(key: &[u8], config: RandomXConfig) -> Result<Self, RandomXError> {
        let base_flags = RandomXFlag::get_recommended_flags();

        let cache_flags = derive_cache_flags(base_flags, &config);
        let dataset_flags = derive_dataset_flags(&config);
        let vm_flags = derive_vm_flags(base_flags, &config, true);

        let cache = RandomXCache::new(cache_flags, key)?;
        let dataset = RandomXDataset::new(dataset_flags, cache.clone(), 0)?;
        let vm = RandomXVM::new(vm_flags, Some(cache.clone()), Some(dataset.clone()))?;

        Ok(Self {
            vm,
            cache,
            dataset: Some(dataset),
            flags_vm: vm_flags,
        })
    }

    /// Tworzy lekki VM (tylko cache – ~256 MiB, wolniejsze hashe).
    ///
    /// Użyteczne do weryfikacji PoW po stronie walidatora.
    pub fn new_light(key: &[u8], config: RandomXConfig) -> Result<Self, RandomXError> {
        let base_flags = RandomXFlag::get_recommended_flags();

        let cache_flags = derive_cache_flags(base_flags, &config);
        // light mode – bez FULL_MEM
        let vm_flags = derive_vm_flags(base_flags, &config, false);

        let cache = RandomXCache::new(cache_flags, key)?;
        let vm = RandomXVM::new(vm_flags, Some(cache.clone()), None)?;

        Ok(Self {
            vm,
            cache,
            dataset: None,
            flags_vm: vm_flags,
        })
    }

    /// Re-init pełnego VM dla nowego klucza (np. nowa epoka).
    ///
    /// Zakładamy, że chcesz dalej FULL_MEM – jeśli nie, zbuduj nowy
    /// engine przez `new_light`.
    pub fn reinit_fast(&mut self, key: &[u8], config: RandomXConfig) -> Result<(), RandomXError> {
        let base_flags = RandomXFlag::get_recommended_flags();

        let cache_flags = derive_cache_flags(base_flags, &config);
        let dataset_flags = derive_dataset_flags(&config);

        let cache = RandomXCache::new(cache_flags, key)?;
        let dataset = RandomXDataset::new(dataset_flags, cache.clone(), 0)?;

        // Zamiast kombinować z reinit_cache / reinit_dataset
        // po prostu tworzymy nowy VM – prościej i czysto.
        let vm_flags = derive_vm_flags(base_flags, &config, true);
        let vm = RandomXVM::new(vm_flags, Some(cache.clone()), Some(dataset.clone()))?;

        self.vm = vm;
        self.cache = cache;
        self.dataset = Some(dataset);
        self.flags_vm = vm_flags;

        Ok(())
    }

    /// Liczy pojedynczy RandomX hash – zwraca 32 bajty.
    pub fn hash(&self, input: &[u8]) -> Result<[u8; 32], RandomXError> {
        let out = self.vm.calculate_hash(input)?;

        if out.len() != 32 {
            // Nie powinno się zdarzyć jeśli librandomx działa poprawnie.
            return Err(RandomXError::Other(format!(
                "Unexpected RandomX hash length: {}",
                out.len()
            )));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        Ok(arr)
    }

    /// Zwraca flagi VM (do debugowania / logów).
    pub fn vm_flags(&self) -> RandomXFlag {
        self.flags_vm
    }

    /// Czy ten engine ma pełny dataset w pamięci.
    pub fn has_dataset(&self) -> bool {
        self.dataset.is_some()
    }
}

/// Flagi dla cache:
/// - JIT + large pages
/// - Argon2 optymalizacje (AVX2 / SSSE3 / fallback)
fn derive_cache_flags(base: RandomXFlag, cfg: &RandomXConfig) -> RandomXFlag {
    let mut flags = RandomXFlag::empty();

    // Przekazujemy optymalizacje Argon2 z base_flags
    if base.contains(RandomXFlag::FLAG_ARGON2_AVX2) {
        flags |= RandomXFlag::FLAG_ARGON2_AVX2;
    } else if base.contains(RandomXFlag::FLAG_ARGON2_SSSE3) {
        flags |= RandomXFlag::FLAG_ARGON2_SSSE3;
    } else if base.contains(RandomXFlag::FLAG_ARGON2) {
        flags |= RandomXFlag::FLAG_ARGON2;
    }

    // Cache może używać JIT + large pages
    if base.contains(RandomXFlag::FLAG_JIT) {
        flags |= RandomXFlag::FLAG_JIT;
    }
    if cfg.use_large_pages {
        flags |= RandomXFlag::FLAG_LARGE_PAGES;
    }

    if flags.is_empty() {
        RandomXFlag::FLAG_DEFAULT
    } else {
        flags
    }
}

/// Flagi dla datasetu:
/// - tylko DEFAULT / LARGE_PAGES (zgodnie z dokumentacją)
fn derive_dataset_flags(cfg: &RandomXConfig) -> RandomXFlag {
    if cfg.use_large_pages {
        RandomXFlag::FLAG_LARGE_PAGES
    } else {
        RandomXFlag::FLAG_DEFAULT
    }
}

/// Flagi dla VM:
/// - tylko LARGEPAGES, HARD_AES, FULL_MEM, JIT, SECURE
///   (bez żadnych ARGON2_* – są ignorowane przez VM i nie są
///    wymienione w docs.RandomXVM::new)
fn derive_vm_flags(base: RandomXFlag, cfg: &RandomXConfig, full_mem: bool) -> RandomXFlag {
    let mut flags = RandomXFlag::empty();

    if cfg.use_large_pages {
        flags |= RandomXFlag::FLAG_LARGE_PAGES;
    }
    if base.contains(RandomXFlag::FLAG_HARD_AES) {
        flags |= RandomXFlag::FLAG_HARD_AES;
    }
    if base.contains(RandomXFlag::FLAG_JIT) {
        flags |= RandomXFlag::FLAG_JIT;
    }
    if cfg.secure_jit {
        flags |= RandomXFlag::FLAG_SECURE;
    }
    if full_mem {
        flags |= RandomXFlag::FLAG_FULL_MEM;
    }

    if flags.is_empty() {
        RandomXFlag::FLAG_DEFAULT
    } else {
        flags
    }
}

/// Porównanie hash < target (little-endian, jak w Twoim poprzednim kodzie).
pub fn hash_less_than(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    // Najwyższy bajt na końcu (little-endian) – lecimy od końca.
    for i in (0..32).rev() {
        if hash[i] < target[i] {
            return true;
        } else if hash[i] > target[i] {
            return false;
        }
    }
    false
}

/// Prosta, jednowątkowa pętla PoW – demo / testy.
///
/// `header_without_nonce` – bajty bloku BEZ 8-bajtowego nonce.
/// `target` – 32-bajtowy próg trudności.
/// Zwraca Some(nonce, hash) albo None jeśli nic nie znalazło w max_iterations.
pub fn mine(
    engine: &RandomXEngine,
    header_without_nonce: &[u8],
    target: &[u8; 32],
    max_iterations: u64,
) -> Result<Option<(u64, [u8; 32])>, RandomXError> {
    let mut buffer = Vec::with_capacity(header_without_nonce.len() + 8);

    for nonce in 0..max_iterations {
        buffer.clear();
        buffer.extend_from_slice(header_without_nonce);
        buffer.extend_from_slice(&nonce.to_le_bytes());

        let hash = engine.hash(&buffer)?;
        if hash_less_than(&hash, target) {
            return Ok(Some((nonce, hash)));
        }
    }

    Ok(None)
}
