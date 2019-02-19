import 'dart:ffi';
import 'types.dart';
import 'helpers.dart';

// See:
// https://commondatastorage.googleapis.com/chromium-boringssl-docs/rsa.h.html

/// RSA_new returns a new, empty RSA object or NULL on error.
///
/// ```c
/// OPENSSL_EXPORT RSA *RSA_new(void);
/// ```
final RSA_new =
    lookup('RSA_new').lookupFunc<RSA Function()>().asFunction<RSA Function()>();

/// RSA_free decrements the reference count of rsa and frees it if the reference
/// count drops to zero.
///
/// ```c
/// OPENSSL_EXPORT void RSA_free(RSA *rsa);
/// ```
final RSA_free = lookup('RSA_free')
    .lookupFunc<Void Function(RSA)>()
    .asFunction<void Function(RSA)>();

//---------------------- Key generation

/// RSA_generate_key_ex generates a new RSA key where the modulus has size bits
/// and the public exponent is e. If unsure, RSA_F4 is a good value for e. If cb
/// is not NULL then it is called during the key generation process. In addition
/// to the calls documented for BN_generate_prime_ex, it is called with event=2
/// when the n'th prime is rejected as unsuitable and with event=3 when a
/// suitable value for p is found.
///
/// It returns one on success or zero on error.
/// ```c
/// OPENSSL_EXPORT int RSA_generate_key_ex(RSA *rsa, int bits, const BIGNUM *e,
///                                        BN_GENCB *cb);
/// ```
final RSA_generate_key_ex = lookup('RSA_generate_key_ex')
    .lookupFunc<Int32 Function(RSA, Int32, BIGNUM, BN_GENCB)>()
    .asFunction<int Function(RSA, int, BIGNUM, BN_GENCB)>();

//---------------------- Utility functions

/// RSA_check_key performs basic validity tests on rsa. It returns one if they
/// pass and zero otherwise. Opaque keys and public keys always pass. If it
/// returns zero then a more detailed error is available on the error queue.
///
/// ```c
/// OPENSSL_EXPORT int RSA_check_key(const RSA *rsa);
/// ```
final RSA_check_key = lookup('RSA_check_key')
    .lookupFunc<Int32 Function(RSA)>()
    .asFunction<int Function(RSA)>();

/// RSAPublicKey_dup allocates a fresh RSA and copies the public key from rsa
/// into it. It returns the fresh RSA object, or NULL on error.
///
/// ```c
/// OPENSSL_EXPORT RSA *RSAPublicKey_dup(const RSA *rsa);
/// ```
final RSAPublicKey_dup = lookup('RSAPublicKey_dup')
    .lookupFunc<RSA Function(RSA)>()
    .asFunction<RSA Function(RSA)>();
