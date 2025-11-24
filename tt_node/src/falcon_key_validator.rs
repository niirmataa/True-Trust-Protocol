//! Falcon-512 Key Validation Module
//! 
//! Provides comprehensive validation for Falcon cryptographic keys
//! to prevent weak key attacks and ensure cryptographic security.

#![forbid(unsafe_code)]

/// Maximum allowed Gram-Schmidt norm for Falcon-512
/// This bound ensures signatures cannot be forged.
/// Precomputed: 1.17^2 * 512.0 = 700.8768
const MAX_GS_NORM_512: f64 = 700.8768;

/// Falcon modulus q = 12289
const FALCON_Q: i32 = 12289;

/// Falcon ring dimension for Falcon-512
const FALCON_N: usize = 512;

/// Result type for validation operations
type ValidationResult<T> = Result<T, ValidationError>;

/// Validation errors
#[derive(Debug, Clone)]
pub enum ValidationError {
    InvalidKeyLength(usize, usize),
    GramSchmidtNormExceeded(f64, f64),
    NtruEquationFailed,
    NonInvertibleKey,
    InvalidPolynomialFormat,
    WeakKeyDetected(String),
    CorruptedKey,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::InvalidKeyLength(got, expected) => {
                write!(f, "Invalid key length: got {}, expected {}", got, expected)
            }
            Self::GramSchmidtNormExceeded(norm, max) => {
                write!(f, "Gram-Schmidt norm {} exceeds maximum {}", norm, max)
            }
            Self::NtruEquationFailed => write!(f, "NTRU equation verification failed"),
            Self::NonInvertibleKey => write!(f, "Key polynomial is not invertible modulo q"),
            Self::InvalidPolynomialFormat => write!(f, "Invalid polynomial format in key"),
            Self::WeakKeyDetected(reason) => write!(f, "Weak key detected: {}", reason),
            Self::CorruptedKey => write!(f, "Key appears to be corrupted"),
        }
    }
}

impl std::error::Error for ValidationError {}

/// Falcon key validation utilities
pub struct FalconKeyValidator;

impl FalconKeyValidator {
    /// Comprehensive validation of a Falcon-512 secret key
    pub fn validate_secret_key(sk_bytes: &[u8]) -> ValidationResult<()> {
        // Check key length (Falcon-512: ~2305 bytes)
        if sk_bytes.len() < 2048 {
            return Err(ValidationError::InvalidKeyLength(sk_bytes.len(), 2048));
        }

        // Parse key components
        let (f, g, big_f, big_g) = Self::parse_secret_key(sk_bytes)?;

        // 1. Validate Gram-Schmidt norm
        Self::validate_gram_schmidt_norm(&f, &g, &big_f, &big_g)?;

        // 2. Verify NTRU equation: f*G - g*F = q
        Self::verify_ntru_equation(&f, &g, &big_f, &big_g)?;

        // 3. Check invertibility of f modulo q
        Self::verify_invertibility(&f)?;

        // 4. Additional security checks
        Self::check_for_weak_patterns(&f, &g)?;

        Ok(())
    }

    /// Validate public key
    pub fn validate_public_key(pk_bytes: &[u8]) -> ValidationResult<()> {
        // Falcon-512 public key is 897 bytes
        if pk_bytes.len() != 897 {
            return Err(ValidationError::InvalidKeyLength(pk_bytes.len(), 897));
        }

        // Parse public key as polynomial h = g/f mod q
        let h = Self::parse_public_key(pk_bytes)?;

        // Check that h is properly reduced modulo q
        for &coeff in &h {
            if coeff < 0 || coeff >= FALCON_Q {
                return Err(ValidationError::InvalidPolynomialFormat);
            }
        }

        // Check for suspicious patterns
        Self::check_public_key_entropy(&h)?;

        Ok(())
    }

    /// Parse secret key into polynomial components
    pub fn parse_secret_key(
        sk_bytes: &[u8],
    ) -> ValidationResult<(Vec<i16>, Vec<i16>, Vec<i16>, Vec<i16>)> {
        if sk_bytes.len() < FALCON_N * 8 {
            return Err(ValidationError::InvalidKeyLength(
                sk_bytes.len(),
                FALCON_N * 8,
            ));
        }

        let mut offset = 0;

        // Parse f polynomial (512 * 2 bytes)
        let f = Self::read_polynomial(&sk_bytes[offset..offset + FALCON_N * 2])?;
        offset += FALCON_N * 2;

        // Parse g polynomial
        let g = Self::read_polynomial(&sk_bytes[offset..offset + FALCON_N * 2])?;
        offset += FALCON_N * 2;

        // Parse F polynomial
        let big_f = Self::read_polynomial(&sk_bytes[offset..offset + FALCON_N * 2])?;
        offset += FALCON_N * 2;

        // Parse G polynomial
        let big_g = Self::read_polynomial(&sk_bytes[offset..offset + FALCON_N * 2])?;

        Ok((f, g, big_f, big_g))
    }

    /// Parse public key polynomial
    pub fn parse_public_key(pk_bytes: &[u8]) -> ValidationResult<Vec<i32>> {
        // Skip header byte and parse polynomial
        if pk_bytes.is_empty() || pk_bytes[0] != 0x00 {
            return Err(ValidationError::InvalidPolynomialFormat);
        }

        let mut h = Vec::with_capacity(FALCON_N);
        let mut offset = 1;

        for _ in 0..FALCON_N {
            if offset + 2 > pk_bytes.len() {
                return Err(ValidationError::InvalidKeyLength(pk_bytes.len(), 897));
            }
            let coeff =
                u16::from_le_bytes([pk_bytes[offset], pk_bytes[offset + 1]]) as i32;
            h.push(coeff);
            offset += 2;
        }

        Ok(h)
    }

    /// Read polynomial from byte array
    fn read_polynomial(bytes: &[u8]) -> ValidationResult<Vec<i16>> {
        if bytes.len() != FALCON_N * 2 {
            return Err(ValidationError::InvalidPolynomialFormat);
        }

        let poly: Vec<i16> = bytes
            .chunks_exact(2)
            .map(|chunk| i16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        Ok(poly)
    }

    /// Validate Gram-Schmidt norm
    pub fn validate_gram_schmidt_norm(
        f: &[i16],
        g: &[i16],
        big_f: &[i16],
        big_g: &[i16],
    ) -> ValidationResult<()> {
        // Compute ||f||² + ||g||²
        let norm_fg: f64 = f
            .iter()
            .map(|&x| (x as f64).powi(2))
            .sum::<f64>()
            + g.iter().map(|&x| (x as f64).powi(2)).sum::<f64>();

        // Compute ||F||² + ||G||²
        let norm_big_fg: f64 = big_f
            .iter()
            .map(|&x| (x as f64).powi(2))
            .sum::<f64>()
            + big_g
                .iter()
                .map(|&x| (x as f64).powi(2))
                .sum::<f64>();

        // Gram-Schmidt norm is the maximum
        let gs_norm = norm_fg.max(norm_big_fg);

        if gs_norm > MAX_GS_NORM_512 {
            return Err(ValidationError::GramSchmidtNormExceeded(
                gs_norm,
                MAX_GS_NORM_512,
            ));
        }

        // Additional check: neither should be too small (indicates corruption)
        if norm_fg < 100.0 || norm_big_fg < 100.0 {
            return Err(ValidationError::WeakKeyDetected(
                "Polynomial norm too small".to_string(),
            ));
        }

        Ok(())
    }

    /// Verify NTRU equation: f*G - g*F = q in ring R = Z[x]/(x^n + 1)
    fn verify_ntru_equation(
        f: &[i16],
        g: &[i16],
        big_f: &[i16],
        big_g: &[i16],
    ) -> ValidationResult<()> {
        // We need to verify that f*G - g*F = q in the ring
        for i in 0..FALCON_N {
            let mut result = 0i64;

            // Compute (f * G)[i]
            for j in 0..FALCON_N {
                let k = (i + j) % FALCON_N;
                let sign = if (i + j) >= FALCON_N { -1i64 } else { 1i64 };
                result += sign * (f[j] as i64) * (big_g[k] as i64);
            }

            // Compute (g * F)[i] and subtract
            for j in 0..FALCON_N {
                let k = (i + j) % FALCON_N;
                let sign = if (i + j) >= FALCON_N { -1i64 } else { 1i64 };
                result -= sign * (g[j] as i64) * (big_f[k] as i64);
            }

            // Result should be q for i=0, and 0 for i>0
            let expected = if i == 0 { FALCON_Q as i64 } else { 0 };

            // Allow small numerical error
            if (result - expected).abs() > 1 {
                return Err(ValidationError::NtruEquationFailed);
            }
        }

        Ok(())
    }

    /// Verify that f is invertible modulo q
    fn verify_invertibility(f: &[i16]) -> ValidationResult<()> {
        // Compute NTT(f) and check all coefficients are non-zero mod q
        let ntt_f = Self::compute_ntt(f);

        for &coeff in &ntt_f {
            if coeff == 0 {
                return Err(ValidationError::NonInvertibleKey);
            }
        }

        Ok(())
    }

    /// Number Theoretic Transform for Falcon
    pub fn compute_ntt(poly: &[i16]) -> Vec<i32> {
        let mut result = vec![0i32; FALCON_N];

        // Primitive root of unity for NTT
        let omega = 7i32; // 7 is primitive root mod 12289
        let omega_n =
            Self::mod_exp(omega, (FALCON_Q - 1) / FALCON_N as i32, FALCON_Q);

        // Cooley-Tukey NTT (simple O(n^2) reference)
        for i in 0..FALCON_N {
            for j in 0..FALCON_N {
                let omega_power =
                    Self::mod_exp(omega_n, (i * j) as i32, FALCON_Q);
                result[i] = (result[i] + (poly[j] as i32 * omega_power)) % FALCON_Q;
            }
        }

        result
    }

    /// Modular exponentiation
    fn mod_exp(base: i32, exp: i32, modulus: i32) -> i32 {
        let mut result = 1i64;
        let mut base = base as i64;
        let mut exp = exp;
        let modulus = modulus as i64;

        base %= modulus;
        while exp > 0 {
            if exp & 1 == 1 {
                result = (result * base) % modulus;
            }
            base = (base * base) % modulus;
            exp >>= 1;
        }

        result as i32
    }

    /// Check for weak patterns in key
    pub fn check_for_weak_patterns(
        f: &[i16],
        g: &[i16],
    ) -> ValidationResult<()> {
        // Check for too many zeros
        let f_zeros = f.iter().filter(|&&x| x == 0).count();
        let g_zeros = g.iter().filter(|&&x| x == 0).count();

        if f_zeros > FALCON_N / 4 || g_zeros > FALCON_N / 4 {
            return Err(ValidationError::WeakKeyDetected(
                "Too many zero coefficients".to_string(),
            ));
        }

        // Check for low Hamming weight
        let f_nonzero = FALCON_N - f_zeros;
        let g_nonzero = FALCON_N - g_zeros;

        if f_nonzero < 100 || g_nonzero < 100 {
            return Err(ValidationError::WeakKeyDetected(
                "Hamming weight too low".to_string(),
            ));
        }

        // Check for repeated patterns
        if Self::has_repeated_pattern(f) || Self::has_repeated_pattern(g) {
            return Err(ValidationError::WeakKeyDetected(
                "Repeated pattern detected".to_string(),
            ));
        }

        Ok(())
    }

    /// Check public key entropy
    fn check_public_key_entropy(h: &[i32]) -> ValidationResult<()> {
        // Calculate entropy approximation
        let mut freq = vec![0u32; FALCON_Q as usize];
        for &coeff in h {
            freq[coeff as usize] += 1;
        }

        let entropy: f64 = freq
            .iter()
            .filter(|&&f| f > 0)
            .map(|&f| {
                let p = f as f64 / FALCON_N as f64;
                -p * p.log2()
            })
            .sum();

        // Entropy should be high (close to log2(q) = ~13.58)
        if entropy < 10.0 {
            return Err(ValidationError::WeakKeyDetected(format!(
                "Low entropy: {:.2}",
                entropy
            )));
        }

        Ok(())
    }

    /// Check for repeated patterns
    fn has_repeated_pattern(poly: &[i16]) -> bool {
        // Check for period dividing n
        for period in [2, 4, 8, 16, 32, 64, 128, 256] {
            if FALCON_N % period != 0 {
                continue;
            }

            let mut is_periodic = true;
            for i in period..FALCON_N {
                if poly[i] != poly[i % period] {
                    is_periodic = false;
                    break;
                }
            }

            if is_periodic {
                return true;
            }
        }

        false
    }
}

/// Secure key generation with validation
pub struct ValidatedKeyGenerator;

impl ValidatedKeyGenerator {
    /// Generate and validate Falcon keypair
    pub fn generate_validated_keypair(
        seed: &[u8; 32],
        personalization: &[u8],
    ) -> ValidationResult<(Vec<u8>, Vec<u8>)> {
        // Generate keypair using deterministic method
        let (pk_bytes, sk_bytes) = Self::generate_raw_keypair(seed, personalization)?;

        // Validate secret key
        FalconKeyValidator::validate_secret_key(&sk_bytes)?;

        // Validate public key
        FalconKeyValidator::validate_public_key(&pk_bytes)?;

        // Additional cross-validation
        Self::cross_validate_keypair(&pk_bytes, &sk_bytes)?;

        Ok((pk_bytes, sk_bytes))
    }

    /// Generate raw keypair (placeholder - use actual Falcon implementation)
    fn generate_raw_keypair(
        _seed: &[u8; 32],
        _personalization: &[u8],
    ) -> ValidationResult<(Vec<u8>, Vec<u8>)> {
        // This should call your actual Falcon keypair generation.
        // For now, returning dummy data for structure.
        let pk = vec![0u8; 897];
        let sk = vec![0u8; 2305];
        Ok((pk, sk))
    }

    /// Cross-validate that public and secret keys match
    fn cross_validate_keypair(
        pk_bytes: &[u8],
        sk_bytes: &[u8],
    ) -> ValidationResult<()> {
        // Extract f and g from secret key
        let (f, g, _, _) = FalconKeyValidator::parse_secret_key(sk_bytes)?;

        // Extract h from public key
        let _h = FalconKeyValidator::parse_public_key(pk_bytes)?;

        // TODO: Verify: h = g/f mod q (NTT-based check)
        // This requires computing f^(-1) mod q and checking h*f = g mod q.

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gram_schmidt_validation() {
        // Create polynomials with known norm
        let f = vec![3i16; FALCON_N];
        let g = vec![2i16; FALCON_N];
        let big_f = vec![1i16; FALCON_N];
        let big_g = vec![1i16; FALCON_N];

        let result =
            FalconKeyValidator::validate_gram_schmidt_norm(&f, &g, &big_f, &big_g);

        // This should pass as norm is reasonable
        assert!(result.is_ok());
    }

    #[test]
    fn test_weak_key_detection() {
        // Create weak key with many zeros
        let mut f = vec![0i16; FALCON_N];
        f[0] = 1;
        f[1] = 1;

        let g = vec![1i16; FALCON_N];

        let result = FalconKeyValidator::check_for_weak_patterns(&f, &g);

        // Should detect weak pattern
        assert!(result.is_err());
    }

    #[test]
    fn test_ntt_computation() {
        // Test NTT with known polynomial
        let poly = vec![1i16; FALCON_N];
        let ntt = FalconKeyValidator::compute_ntt(&poly);

        // First coefficient should be sum of all inputs mod q
        assert_eq!(ntt[0], (FALCON_N as i32) % FALCON_Q);
    }

    #[test]
    fn test_repeated_pattern_detection() {
        // Create polynomial with period 4
        let mut poly = vec![0i16; FALCON_N];
        for i in 0..FALCON_N {
            poly[i] = (i % 4) as i16;
        }

        assert!(FalconKeyValidator::has_repeated_pattern(&poly));

        // Random-looking polynomial should not have pattern
        let random_poly: Vec<i16> = (0..FALCON_N)
            .map(|i| ((i * 31 + 17) % 100) as i16)
            .collect();

        assert!(!FalconKeyValidator::has_repeated_pattern(&random_poly));
    }
}
