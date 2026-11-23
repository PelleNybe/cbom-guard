#include <openssl/evp.h>
#include <openssl/rsa.h>

void vulnerable_cpp_crypto() {
    EVP_PKEY* pkey = EVP_RSA_gen(2048);
    const EVP_MD* md = EVP_md5();
    (void)pkey;
    (void)md;
}
