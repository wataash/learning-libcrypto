OPENSSL_DIR=/Users/danielbevenius/work/security/build_master
OPENSSL_INCLUDE_DIR=$(OPENSSL_DIR)/include
OPENSSL_LIB_DIR=$(OPENSSL_DIR)/lib

basic: basic.c
	clang -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lcrypto

ssl_method: ssl_method.c
	clang -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lssl -lcrypto

hmac: hmac.c
	clang -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lcrypto

digest: digest.c
	clang -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lcrypto

sign: sign.c
	clang -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lcrypto

private: private.c
	clang -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lcrypto

socket: socket.c
	clang -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lcrypto

ssl: ssl.c
	clang -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lssl -lcrypto

engine: engine.c
	clang -O0 -g -fPIC -I$(OPENSSL_INCLUDE_DIR) -c $< -o $@.o
	clang -shared -o $@.so -L$(OPENSSL_LIB_DIR) -lcrypto $@.o

random_bytes: random_bytes.c
	clang -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lssl -lcrypto

bio: bio.c
	clang -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lssl -lcrypto

bio_ssl: bio_ssl.c
	clang -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lssl -lcrypto

derive: derive.c
	clang -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lssl -lcrypto

distribution: distribution.cc
	clang++ -std=c++14 -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lssl -lcrypto

generator: generator.cc
	clang++ -std=c++14 -O0 -g -I$(OPENSSL_INCLUDE_DIR) $< -o $@ -L$(OPENSSL_LIB_DIR) -lssl -lcrypto

.PHONY: clean

clean:
	@rm -f basic socket ssl engine hmac digest sign private random_bytes ssl_method derive
