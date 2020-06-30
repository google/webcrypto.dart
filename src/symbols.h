#ifndef WEBCRYPTO_SYMBOLS_H
#define WEBCRYPTO_SYMBOLS_H

#include <stddef.h>

// BoringSSL headers
#include <openssl/crypto.h>
#include <openssl/aead.h>
#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/cipher.h>
#include <openssl/digest.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

// Symbol lookup table defined in `symbols.generated.h`, with indexes matching
// the enum values in `lib/src/boringssl/lookup/symbols.generated.dart`.
extern void *_webcrypto_symbol_table[];

#endif // WEBCRYPTO_SYMBOLS_H
