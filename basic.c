#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

int encrypt(unsigned char *plaintext,
            int plaintext_len,
            unsigned char *key,
            unsigned char *iv,
            unsigned char *ciphertext);

int decrypt(unsigned char *ciphertext,
            int ciphertext_len,
            unsigned char *key,
            unsigned char *iv,
            unsigned char *plaintext);

void handleErrors(void);

int main(int arc, char *argv[]) {
  // https://www.openssl.org/docs/manmaster/man3/ERR_load_crypto_strings.html
  // deprecated since 1.1.0
  /* Load the human readable error strings for libcrypto */
  ERR_load_crypto_strings();

  // https://www.openssl.org/docs/manmaster/man3/OpenSSL_add_all_algorithms.html
  // deprecated since 1.1.0
  /* Load all digest and cipher algorithms */
  OpenSSL_add_all_algorithms();

  // https://www.openssl.org/docs/manmaster/man3/OPENSSL_no_config.html
  // deprecated since 1.1.0
  /* Load config file, and other important initialisation */
  //OPENSSL_config(NULL);
  OPENSSL_no_config();

  unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
  unsigned char *iv = (unsigned char *)"someIV";
  unsigned char *plaintext = (unsigned char *) "Bajja";
  unsigned char ciphertext[128];
  unsigned char decryptedtext[128];

  int decryptedtext_len, ciphertext_len;
  ciphertext_len = encrypt(plaintext, strlen ((char *)plaintext), key, iv, ciphertext);
  printf("Ciphertext is:\n");
  BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

  decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
  decryptedtext[decryptedtext_len] = '\0';
  printf("Decrypted text is:\n");
  printf("%s\n", decryptedtext);

  // https://www.openssl.org/docs/manmaster/man3/CONF_modules_unload.html
  // Deprecated since OpenSSL 1.1.0
  CONF_modules_unload(1);

  // https://www.openssl.org/docs/manmaster/man3/EVP_cleanup.html
  // deprecated in OpenSSL 1.1.0 by OPENSSL_init_crypto()
  // https://www.openssl.org/docs/manmaster/man3/OPENSSL_init_crypto.html
  /* Removes all digests and ciphers */
  EVP_cleanup();

  /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
  CRYPTO_cleanup_all_ex_data();

  // https://www.openssl.org/docs/manmaster/man3/ERR_remove_state.html
  // Deprecated since OpenSSL 1.0.0
  // ERR_remove_state();

  // https://www.openssl.org/docs/manmaster/man3/ERR_free_strings.html
  // Deprecated since OpenSSL 1.1.0,
  /* Remove error strings */
  ERR_free_strings();

  return 0;
}

int encrypt(unsigned char* plaintext,
            int plaintext_len,
            unsigned char* key,
            unsigned char* iv,
            unsigned char* ciphertext) {
  EVP_CIPHER_CTX* ctx;
  int len;
  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) {
    handleErrors();
  }

  int tmp = EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
  (void)tmp;
  ERR_print_errors_fp(stderr); // 0:error:0607B083:digital envelope routines:EVP_CipherInit_ex:no cipher set:../crypto/evp/evp_enc.c:148:
  ERR_print_errors_fp(stderr); // (noop)

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
    handleErrors();
  }

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
    handleErrors();
  }
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
    handleErrors();
  }
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

int decrypt(unsigned char* ciphertext,
            int ciphertext_len,
            unsigned char* key,
            unsigned char* iv,
            unsigned char* plaintext) {
  EVP_CIPHER_CTX* ctx;
  int len;
  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) {
    handleErrors();
  }

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
    handleErrors();
  }

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
    handleErrors();
  }
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
    handleErrors();
  }
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}

void handleErrors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}

