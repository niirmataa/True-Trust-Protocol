/*
 * Small wrapper to expose `tt_falcon512_*` symbols that the Rust crate
 * expects and to allow installing a deterministic `fill` callback used
 * by the RNG bridge.
 */

#include <stddef.h>
#include <stdint.h>

/* Forward declarations of PQClean API functions we call. */
int PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen,
                                                 const uint8_t *m, size_t mlen,
                                                 const uint8_t *sk);
int PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen,
                                              const uint8_t *m, size_t mlen,
                                              const uint8_t *pk);

/* Global callback pointer used by modified randombytes.c */
void (*tt_fill_cb)(uint8_t *, size_t) = NULL;

/* Install or remove the fill callback */
void tt_set_fill_cb(void (*cb)(uint8_t *, size_t)) {
    tt_fill_cb = cb;
}

/* Exposed functions expected by Rust FFI */
int tt_falcon512_keypair_seeded(uint8_t *pk, uint8_t *sk,
                                void (*fill)(uint8_t *, size_t)) {
    tt_set_fill_cb(fill);
    int rc = PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk, sk);
    tt_set_fill_cb(NULL);
    return rc;
}

int tt_falcon512_sign_seeded(uint8_t *sig, size_t *siglen,
                             const uint8_t *m, size_t mlen,
                             const uint8_t *sk,
                             void (*fill)(uint8_t *, size_t)) {
    tt_set_fill_cb(fill);
    int rc = PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
    tt_set_fill_cb(NULL);
    return rc;
}

int tt_falcon512_verify(const uint8_t *sig, size_t siglen,
                        const uint8_t *m, size_t mlen,
                        const uint8_t *pk) {
    return PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}
