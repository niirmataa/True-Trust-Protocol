#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "../pqclean/crypto_sign/falcon-512/clean/api.h"

// Thread-local callback used by PQClean's `randombytes` hook.
// SECURITY: This MUST be set before any cryptographic operation.
static void (*g_fill_bytes)(uint8_t *out, size_t outlen) = NULL;

/// Replacement for PQClean's randombytes implementation.
/// Delegates to the Rust-provided callback when available.
///
/// # Security - CRITICAL!
///
/// If no RNG callback is set, this function calls abort() to prevent
/// generating cryptographically insecure keys/signatures with zero-filled
/// randomness. This is a fail-safe mechanism that should never trigger
/// in correct usage.
int PQCLEAN_randombytes(uint8_t *out, size_t outlen) {
    if (!g_fill_bytes) {
        // FATAL SECURITY ERROR: No RNG source registered!
        // This should never happen if Rust code is correct.
        // Abort immediately rather than generating insecure output.
        abort();
    }

    g_fill_bytes(out, outlen);
    return 0;
}

/// Generate Falcon-512 keypair with seeded RNG
///
/// # Parameters
/// - pk: Output buffer for public key (897 bytes)
/// - sk: Output buffer for secret key (1281 bytes)
/// - fill: Callback function to fill buffers with random bytes
///
/// # Returns
/// - 0 on success
/// - Non-zero on failure
int tt_falcon512_keypair_seeded(
    uint8_t *pk,
    uint8_t *sk,
    void (*fill)(uint8_t *, size_t))
{
    // Temporarily install the RNG callback
    g_fill_bytes = fill;

    // Generate keypair using PQClean
    int rc = PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk, sk);

    // Clear the callback immediately after use
    g_fill_bytes = NULL;

    return rc;
}

/// Sign message with Falcon-512 using seeded RNG
///
/// # Parameters
/// - sig: Output buffer for signature (max 690 bytes)
/// - siglen: Pointer to receive actual signature length
/// - m: Message to sign
/// - mlen: Message length
/// - sk: Secret key (1281 bytes)
/// - fill: Callback function to fill buffers with random bytes
///
/// # Returns
/// - 0 on success
/// - Non-zero on failure
int tt_falcon512_sign_seeded(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk,
    void (*fill)(uint8_t *, size_t))
{
    // Temporarily install the RNG callback
    g_fill_bytes = fill;

    // Generate signature using PQClean
    int rc = PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);

    // Clear the callback immediately after use
    g_fill_bytes = NULL;

    return rc;
}

/// Verify Falcon-512 signature
///
/// # Parameters
/// - sig: Signature to verify
/// - siglen: Signature length
/// - m: Message that was signed
/// - mlen: Message length
/// - pk: Public key (897 bytes)
///
/// # Returns
/// - 0 if signature is valid
/// - Non-zero if signature is invalid
int tt_falcon512_verify(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *pk)
{
    return PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}
