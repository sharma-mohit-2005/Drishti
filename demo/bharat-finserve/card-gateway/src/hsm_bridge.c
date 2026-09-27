/* card-gateway: bridges the switch to the HSM for PIN block handling. */
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>

#define GATEWAY_RSA_BITS 2048

RSA *gateway_key(void) {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, GATEWAY_RSA_BITS, e, NULL);
    return rsa;
}

EC_KEY *terminal_key(void) {
    return EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
}

const EVP_MD *pin_digest(void) {
    return EVP_sha1();
}

const EVP_CIPHER *track_cipher(void) {
    return EVP_aes_128_cbc();
}
