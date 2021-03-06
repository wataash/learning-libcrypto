#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <stdio.h>

long bio_callback(BIO *b,
                  int oper,
                  const char *argp,
                  size_t len,
                  int argi,
                  long argl,
                  int ret,
                  size_t *processed) {
  printf("bio_callback[bio_method_name=%s, operation=%d]\n", BIO_method_name(b), oper);
  return ret;
}

int main(int arc, char *argv[]) {

  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_no_config();
  SSL_CTX* ctx;

  printf("Creating SSL_CTX...\n");

  ctx = SSL_CTX_new(SSLv23_client_method());

  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();

  return 0;
}
