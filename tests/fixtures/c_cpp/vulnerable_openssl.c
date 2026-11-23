#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>

void vulnerable_c_crypto(void) {
    /* Comment mentioning EVP_md5() must not trigger */
    EVP_PKEY *rsa_key = EVP_RSA_gen(2048);
    EVP_PKEY *ec_key = EVP_EC_gen("P-256");
    const EVP_MD *md = EVP_sha1();
    const EVP_CIPHER *legacy = EVP_des_ede3_cbc();
    const EVP_CIPHER *safe = EVP_aes_256_gcm();
    (void)rsa_key;
    (void)ec_key;
    (void)md;
    (void)legacy;
    (void)safe;
}
