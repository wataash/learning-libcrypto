### Learning libcrypto
The sole purpose of this project is to learn OpenSSL's libcryto library


### Building OpenSSL
I've been building OpenSSL using the following configuration:

    $ ./Configure --debug --prefix=/Users/danielbevenius/work/security  --libdir="openssl" darwin64-x86_64-cc

This might look a little odd but allows me to avoid the install step which is pretty slow
and also takes up space on my system. With the followig I can simply make:

To configure and install to a build directory:

    $ ./Configure --debug --prefix=/Users/danielbevenius/work/security/build_1_1_0f darwin64-x86_64-cc

    $ make 

Optionally install:

    $ make install

This is nice so when building a tag and not having to rebuild it again.

The the library location can be specified using `-L` like this:

    -L$(/Users/danielbevenius/work/security/openssl)

You can see how this is used the [Makefile](./makefile).

### Building

    $ make

### Show shared libraries used

    $ export DYLD_PRINT_LIBRARIES=y

### Inspect the shared libraries of an executable

    $ otool -L basic
    basic:
      /Users/danielbevenius/work/security/openssl/libcrypto.1.1.dylib (compatibility version 1.1.0, current version 1.1.0)
      /usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1226.10.1)

### Debugging

    $ lldb basic 
    (lldb) breakpoint set  -f basic.c -l 21

### ctags

    $ ctags -R . /path/to/openssl/


### Find version of Openssl library (static of dynamic)

    $ strings libopenssl.a | grep "^OpenSSL"
    OpenSSL 1.0.2k  26 Jan 2017


### Troubleshooting SSL errors:

    $ ./ssl
    failed to create SSL_CTX
    140735145844816:error:140A90A1:SSL routines:func(169):reason(161):ssl_lib.c:1966:
    $ openssl errstr 0x140A90A1
    error:140A90A1:SSL routines:SSL_CTX_new:library has no ciphers

In this case I'd missed out [initializing](https://wiki.openssl.org/index.php/Library_Initialization) the library.



### ssllib
To make a tls connection you need a SSL_CTX and an SSL pointer. You also have to initialize the
SSL library:

    SSL_CTX* ctx;

This is a struct declared in openssl/include/openssl/ssh.h and contains the SSL_METHOD to be used
, the list of ciphers, a pointer ot a x509_store_st (the cert store)

    SSL* ssl
    SSL_library_init();

    ctx = SSL_CTX_new(SSLv23_client_method);

    SSL_CTX_load_verify_locations(ctx, "/path/to/ca.pem", NULL);

Let's take a closer look at that last call. It will end up in ssl_lib.c:

    return (X509_STORE_load_locations(ctx->cert_store, CAfile, CApath));

Which will delegate to x509_d2.c:

    int X509_STORE_load_locations(X509_STORE *ctx, 
                                  const char *file,
                                  const char *path) {

X509_STORE is a struct defined in x509/x509_vfy.h. This structure holds a cache of trusted certs, has functions like
verify, verify_cb, get_issuer, check_issued, check_revocation, get_crl, check_crl, lookup_certs.

In my example ssl.c I'm not using an X509_STORE, why is that?
Well there is a X509_STORE create implicitely when calling `SSL_CTX_load_verify_locations`, that call will delegate to (ssl_lib.c):

    SSL_CTX_load_verify_locations(ctx, "TrustStore.pem", NULL)

    int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath) {
        return return (X509_STORE_load_locations(ctx->cert_store, CAfile, CApath));
    }

In our case this call will end up in x509_d2.c:

    X509_LOOKUP *lookup;
    if (file != NULL) {
        lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_file());

So what is a X509_LOOKUP?
This is a struct used to store the lookup method, it has state to see if it has been 
initialized, an owning X509_STORE.
The actual look up is done in x509/x509_lu.c which takes a pointer to a X509_STORE and
a X509_LOOKUP_METHOD. 

Remember that I said I'm not using a X509_STORE, but apperently I am
because the SSL_CTX will have a cert_store:

    struct ssl_ctx_st {
    ....
        struct x509_store_st /* X509_STORE */ *cert_store;

When we create a new SSL_CTX we call SSL_CTX_new (ssl/ssl_lib.c) with a pointer to a
SSL_METHOD to be used. This function will allocate a new SSL_CTX:

    ret = (SSL_CTX *)OPENSSL_malloc(sizeof(SSL_CTX));
    ...
    ret->cert_store = NULL;

But later in the same function we have:

    ret->cert_store = X509_STORE_new();

Back to our investigation of loading...

We are loading from a file and the funtion X509_load_cert_crl_file in crypto/x509/by_file.c
we create a new pointer to BIO with the file name:

    STACK_OF(X509_INFO) *inf;
    X509_INFO *itmp;

    in = BIO_new_file(file, "r");
    ... // error handling
    for (i = 0; i < sk_X509_INFO_num(inf); i++) {
       itmp = sk_X509_INFO_value(inf, i);
       if (itmp->x509) {
           X509_STORE_add_cert(ctx->store_ctx, itmp->x509);
           count++;
       }
       if (itmp->crl) {
           X509_STORE_add_crl(ctx->store_ctx, itmp->crl);
           count++;
       }
   }

So the above will loop through all the certificates found in `TrustStore.pem` which is:

    (lldb) p *inf
    (stack_st_X509_INFO) $63 = {
      stack = {
      num = 13
      data = 0x000000010030c970
      sorted = 0
      num_alloc = 16
      comp = 0x0000000000000000
    }
  }

Which we can verify that there are 13 in that file.
Notice that we are adding them using X509_STORE_add_cert. So what does a cert look like 
in code: 

    X509_OBJECT *obj;
    obj = (X509_OBJECT *)OPENSSL_malloc(sizeof(X509_OBJECT));
 
Every X509_OBJECT has a reference count. 


### X509_up_ref
What does this do?
    

### Environment variables
There are two environment variables that can be used (openssl/crypto/cryptlib.h):

    # define X509_CERT_DIR_EVP        "SSL_CERT_DIR"
    # define X509_CERT_FILE_EVP       "SSL_CERT_FILE"

When you do a X509_STORE_load_file and the method used is ctrl (by_file_ctrl)


### Engine

    $ make engine
    $ ../openssl/apps/openssl engine -t -c `pwd`/engine.so
    (/Users/danielbevenius/work/security/learning-libcrypto/engine.so) OpenSSL Engine example
     [ available ]


### Message Digest 
Is a cryptographic hash function which takes a string of any length as input and produces a fixed length hash value. A message digest is a fixed size numeric representation of the contents of a message
An example of this can be found in digest.c

    md = EVP_get_digestbyname("SHA256");

The implementation of this can be found in openssl/crypto/evp/names.c:

    const EVP_MD *cp;
    ... 
    cp = (const EVP_MD *)OBJ_NAME_get(name, OBJ_NAME_TYPE_MD_METH);
    return (cp);

The extra parentheses are just a convention and could be skipped.
So how would one get back the name, or what would one do with the type?
`crypto/evp/evp_lib.c` contains functions that can be used to get the type
of a Message Digest:

    int EVP_MD_type(const EVP_MD* md) {
      return md->type;
    }

The structs are not public but you can find them in `crypto/include/internal/evp_int.h`:

    struct evp_md_st {
      int type;
      int pkey_type;
      int md_size;
      unsigned long flags;
      int (*init) (EVP_MD_CTX *ctx);
      int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
      int (*final) (EVP_MD_CTX *ctx, unsigned char *md);
      int (*copy) (EVP_MD_CTX *to, const EVP_MD_CTX *from);
      int (*cleanup) (EVP_MD_CTX *ctx);
      int block_size;
      int ctx_size;               /* how big does the ctx->md_data need to be */
      /* control function */
      int (*md_ctrl) (EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
    } /* EVP_MD */ ;


Next lets look at this statement:

    mdctx = EVP_MD_CTX_new();

The impl can be found in `crypto/evp/digest.c':

    return OPENSSL_zalloc(sizeof(EVP_MD_CTX));

This calls memset() to zero the memory before returning:

    void *ret = CRYPTO_malloc(num, file, line);
    ...
    if (ret != NULL)
      memset(ret, 0, num);
    return ret;

So we are allocating memory for the context only at this stage.

The underlying private struct can be found in `crypto/evp/evp_locl.h`:

    struct evp_md_ctx_st {
      const EVP_MD *digest;
      ENGINE *engine;             /* functional reference if 'digest' is * ENGINE-provided */
      unsigned long flags;
      void *md_data;
      /* Public key context for sign/verify */
      EVP_PKEY_CTX *pctx;
      /* Update function: usually copied from EVP_MD */
      int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
    } /* EVP_MD_CTX */ ;

But, remember we have only allocated memory and zeroed out the structs fields nothing more.
Next, lets take a look at:

    EVP_DigestInit_ex(mdctx, md, engine);

We are passing in our pointer to the newly allocated EVP_MD_CTX struct, and a pointer to a 
Message Digest EVP_MD.
The impl can be found in `crypto/evp/digest.c':

     int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl) {

     }

There is also a function named `EVP_DigestInit(EVP_MD_CTX* ctx, const EVP_MD* type)` which does:

    int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type)
    {
      EVP_MD_CTX_reset(ctx);
      return EVP_DigestInit_ex(ctx, type, NULL);
    }

So it calls reset on the EVP_MD_CTX_reset which in our case is not required as we are not reusing the context. But that is the only thing that differs.

    ctx->digest = type;
    if (!(ctx->flags & EVP_MD_CTX_FLAG_NO_INIT) && type->ctx_size) {
      ctx->update = type->update;
      ctx->md_data = OPENSSL_zalloc(type->ctx_size);
      if (ctx->md_data == NULL) {
        EVPerr(EVP_F_EVP_DIGESTINIT_EX, ERR_R_MALLOC_FAILURE);
        return 0;
      }
    }

Just to clarify this, `ctx` is a pointer to EVP_MD_CTX and `type` is a const pointer to EVP_MD.
`update` of the EVP_MD_CTX is set to the EVP_MD's update so I guess either one can be used after this.
`ctx->md_data` is allocated for the EVP_MD_CTX member `md_data` and the size used is the size for the type of EVP_MD being used. 

     return ctx->digest->init(ctx);

This will end up in m_sha1.c:

    static int init256(EVP_MD_CTX *ctx) {
      return SHA256_Init(EVP_MD_CTX_md_data(ctx));
    }

Next we have:

    EVP_DigestUpdate(mdctx, msg1, strlen(msg1));

This will call:

    return ctx->update(ctx, data, count);

Which we recall from before in our case is the same as the EVP_MD update function which means
that we will end up again in `m_sha1.c`:

    static int update256(EVP_MD_CTX *ctx, const void *data, size_t count) {
      return SHA256_Update(EVP_MD_CTX_md_data(ctx), data, count);
   }

Notice the getting of md_data and passing that along which will be the HASH_CTX* in:

    int HASH_UPDATE(HASH_CTX *c, const void *data_, size_t len) {
    }

This will hash the passed in data and store that hash in the `md_data` field. This can be done any
number of times.

    EVP_DigestFinal_ex(mdctx, md_value, &md_len);

    (lldb) p md_value
    (unsigned char [64]) $0 = "\x01"

Recall that this local variable is initialized here:

    unsigned char md_value[EVP_MAX_MD_SIZE];

Which can be found in include/openssl/evp.h:

    # define EVP_MAX_MD_SIZE                 64/* longest known is SHA512 */

`EVP_DigestFinal_ex` will check this size:

    OPENSSL_assert(ctx->digest->md_size <= EVP_MAX_MD_SIZE);
    ret = ctx->digest->final(ctx, md);

    if (size != NULL)
      *size = ctx->digest->md_size;

So one does not have to pass in the size and is should be possible to get the size after
calling this operation using EVP_MD_size(md) or EVP_MD_CTX_size(mdctx).

### Message Authentication Code (MAC)
Is a message digest that is encrypted. If a symmetric key is used it is know as a Message Authentication Code (MAC) as it can prove that the message has not been tampered with.

### Digital signature
Is a message digest that is encrypted.
A message can be signed with the private key and sent with the message itself. The receiver then decrypts the signature before comparing it a locally generated digest.

    EVP_SignInit_ex(mdctx, md, engine);

Interesting is that this will call `EVP_DigestInit_ex` just like in our message digest walkthrough. This is because this is actually a macro defined in `include/openssl/evp.h`:

    # define EVP_SignInit_ex(a,b,c)          EVP_DigestInit_ex(a,b,c)
    # define EVP_SignInit(a,b)               EVP_DigestInit(a,b)
    # define EVP_SignUpdate(a,b,c)           EVP_DigestUpdate(a,b,c)

So we already know what `EVP_SignInit_ex` and `EVP_SignUpdate` do. 
But `EVP_SignFinal` is implemented in `crypto/evp/p_sign.c`:

    EVP_SignFinal(mdctx, sig, &sig_len, pkey);

    int EVP_SignFinal(EVP_MD_CTX *ctx, unsigned char *sigret,
                  unsigned int *siglen, EVP_PKEY *pkey) {
    }

### Private key
EVP_PKEY is a general private key reference without any particular algorithm.

    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_free(pkey);

There is also a function to increment the ref count named `EVP_PKEY_up_ref()`.
But new only creates an empty structure for (../openssl/crypto/include/internal/evp_int.h):

    struct evp_pkey_st {
      int type;
      int save_type;
      CRYPTO_REF_COUNT references;
      const EVP_PKEY_ASN1_METHOD *ameth;
      ENGINE *engine;
      union {
        void *ptr;
        # ifndef OPENSSL_NO_RSA
          struct rsa_st *rsa;     /* RSA */
        # endif
        # ifndef OPENSSL_NO_DSA
          struct dsa_st *dsa;     /* DSA */
        # endif
        # ifndef OPENSSL_NO_DH
          struct dh_st *dh;       /* DH */
        # endif
        # ifndef OPENSSL_NO_EC
          struct ec_key_st *ec;   /* ECC */
        # endif
      } pkey;
      int save_parameters;
      STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
      CRYPTO_RWLOCK *lock;
    } /* EVP_PKEY */ ;

Recall that a union allows for the usage of a single memory location but for different data types.
So set the private key on of the following functions is used:

    int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, RSA *key);
    int EVP_PKEY_set1_DSA(EVP_PKEY *pkey, DSA *key);
    int EVP_PKEY_set1_DH(EVP_PKEY *pkey, DH *key);
    int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, EC_KEY *key);

Why are these called `set1_`? Lets take a look at `EVP_PKEY_set1_RSA` (openssl/crypto/evp/p_lib.c):

    int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, RSA *key) {
      int ret = EVP_PKEY_assign_RSA(pkey, key);
      if (ret)
        RSA_up_ref(key);
      return ret;
    }

Notice that the ref count is updated. There are then two getters:

    RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey)
    RSA *EVP_PKEY_get1_RSA(EVP_PKEY *pkey)

Where `EVP_PKEY_get1_RSA` will call EVP_PKEY_get0_RSA and then increment the ref count. This is
the only reason I can think of that these function have 1 and 0. 1 for functions that update the ref count and 0 for those that dont. 
"In accordance with the OpenSSL naming convention the key obtained from or assigned to the pkey using the 1 functions must be freed as well as pkey."


### BIGNUM (BN)
Is needed for cryptographic functions that require arithmetic on large numbers without loss of preciesion. A BN can hold an arbitary sized integer and implements all operators.

    BIGNUM* three = BN_new();
    BN_set_word(three, 3);
    BN_free(three);

### TicketKey
Is a way to offload a TLS server when session re-joining is in use. Instead of the server having to keep track of a session id and the associated info the server generates this info and sends it back to the client with stores it.
The client indicates that it supports this mechanism by including a SessionTicket TLS extension in the ClientHello message.

### RAND_bytes
OpenSSL provides a number of software based random number generators based on a variety of sources.
The library can use custom hardware if the hardware has an ENIGNE interface.

Entropy is the measure of randomness in a sequence of bits.


### PEM_read_bio_X509

    X509 *x509 = PEM_read_bio_X509(bp, NULL, pass_cb, NULL);

This will end up in pem_x509.c and it is simply:

    #include <stdio.h>
    #include "internal/cryptlib.h"
    #include <openssl/bio.h>
    #include <openssl/evp.h>
    #include <openssl/x509.h>
    #include <openssl/pkcs7.h>
    #include <openssl/pem.h>

    IMPLEMENT_PEM_rw(X509, X509, PEM_STRING_X509, X509)

So this is a macro which can be found in `openssl/pem.h`:

    # define IMPLEMENT_PEM_rw(name, type, str, asn1) \
            IMPLEMENT_PEM_read(name, type, str, asn1) \
            IMPLEMENT_PEM_write(name, type, str, asn1)

So, we can see that this is made up of two macros (will the macro in pem_x509 will be substituted by this by the preprocessor that is.


`pem_oth.c'
    void *PEM_ASN1_read_bio(d2i_of_void *d2i, const char *name, BIO *bp, void **x, pem_password_cb *cb, void *u)

#### Generating a selfsigned cert

    $ ../openssl/apps/openssl req  -nodes -new -x509  -keyout server.key -out server.cert


### FIPS
Download openssl-fips-2.0.16 and unzip:

   $ ./Configure darwin64-x86_64-cc --prefix=/Users/danielbevenius/work/security/build_1_0_2k
   $ make
   $ make install

This example will install to the `build_1_0_2k` directory so changes this as required.

Next, you'll have to build the OpenSSL library with fips support and specify the installation directory which was used above:

   $ ./Configure fips shared no-ssl2 --debug --prefix=/Users/danielbevenius/work/security/build_1_0_2k darwin64-x86_64-cc --with-fipsdir=/Users/danielbevenius/work/security/build_1_0_2k
   $ make depend
   $ make
   $ make install_sw

