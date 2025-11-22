#include <stddef.h>
#include <stdint.h>

#include "../pqclean/crypto_sign/falcon-512/clean/api.h"

// Thread-local callback used by PQClean's `randombytes` hook.
static void (*g_fill_bytes)(uint8_t *out, size_t outlen) = NULL;

// Replacement for PQClean's randombytes implementation.
// Delegates to the Rust-provided callback when available.
int PQCLEAN_randombytes(uint8_t *out, size_t outlen) {
    if (g_fill_bytes) {
        g_fill_bytes(out, outlen);
    } else {
        // Fallback: deterministic zeroing to avoid UB; callers should always set the callback.
        for (size_t i = 0; i < outlen; i++) {
            out[i] = 0;
        }
    }

    return 0;
}

int tt_falcon512_keypair_seeded(
    uint8_t *pk,
    uint8_t *sk,
    void (*fill)(uint8_t *, size_t)) {
    g_fill_bytes = fill;
    int rc = PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk, sk);
    g_fill_bytes = NULL;
    return rc;
}

int tt_falcon512_sign_seeded(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk,
    void (*fill)(uint8_t *, size_t)) {
    g_fill_bytes = fill;
    int rc = PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
    g_fill_bytes = NULL;
    return rc;
}

int tt_falcon512_verify(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *pk) {
    return PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}
