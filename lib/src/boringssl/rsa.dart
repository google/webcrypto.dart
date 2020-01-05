import 'dart:ffi';
import 'types.dart';
import 'helpers.dart';

// See:
// https://commondatastorage.googleapis.com/chromium-boringssl-docs/rsa.h.html

/// RSA_new returns a new, empty RSA object or NULL on error.
///
/// ```c
/// RSA *RSA_new(void);
/// ```
final RSA_new = lookup('RSA_new')
    .lookupFunc<Pointer<RSA> Function()>()
    .asFunction<Pointer<RSA> Function()>();

/// RSA_free decrements the reference count of rsa and frees it if the reference
/// count drops to zero.
///
/// ```c
/// void RSA_free(RSA *rsa);
/// ```
final RSA_free = lookup('RSA_free')
    .lookupFunc<Void Function(Pointer<RSA>)>()
    .asFunction<void Function(Pointer<RSA>)>();

//---------------------- Properties.

/// RSA_get0_key sets *out_n, *out_e, and *out_d, if non-NULL, to rsa's modulus,
/// public exponent, and private exponent, respectively. If rsa is a public key,
/// he private exponent will be set to NULL.
///
/// ```c
/// OPENSSL_EXPORT void RSA_get0_key(const RSA *rsa, const BIGNUM **out_n,
///                                  const BIGNUM **out_e, const BIGNUM **out_d);
/// ```
final RSA_get0_key = lookup('RSA_get0_key')
    .lookupFunc<
        Void Function(
      Pointer<RSA>,
      Pointer<Pointer<BIGNUM>>,
      Pointer<Pointer<BIGNUM>>,
      Pointer<Pointer<BIGNUM>>,
    )>()
    .asFunction<
        void Function(
      Pointer<RSA>,
      Pointer<Pointer<BIGNUM>>,
      Pointer<Pointer<BIGNUM>>,
      Pointer<Pointer<BIGNUM>>,
    )>();

/// RSA_get0_factors sets *out_p and *out_q, if non-NULL, to rsa's prime
/// factors. If rsa is a public key, they will be set to NULL.
///
/// ```c
/// OPENSSL_EXPORT void RSA_get0_factors(const RSA *rsa, const BIGNUM **out_p,
///                                      const BIGNUM **out_q);
/// ```
final RSA_get0_factors = lookup('RSA_get0_factors')
    .lookupFunc<
        Void Function(
      Pointer<RSA>,
      Pointer<Pointer<BIGNUM>>,
      Pointer<Pointer<BIGNUM>>,
    )>()
    .asFunction<
        void Function(
      Pointer<RSA>,
      Pointer<Pointer<BIGNUM>>,
      Pointer<Pointer<BIGNUM>>,
    )>();

/// RSA_get0_crt_params sets *out_dmp1, *out_dmq1, and *out_iqmp, if non-NULL,
/// to rsa's CRT parameters. These are d (mod p-1), d (mod q-1) and q^-1
/// (mod p), respectively. If rsa is a public key, each parameter will be set
/// to NULL.
///
/// ```c
/// OPENSSL_EXPORT void RSA_get0_crt_params(const RSA *rsa, const BIGNUM **out_dmp1,
///                                         const BIGNUM **out_dmq1,
///                                         const BIGNUM **out_iqmp);
/// ```
final RSA_get0_crt_params = lookup('RSA_get0_crt_params')
    .lookupFunc<
        Void Function(
      Pointer<RSA>,
      Pointer<Pointer<BIGNUM>>,
      Pointer<Pointer<BIGNUM>>,
      Pointer<Pointer<BIGNUM>>,
    )>()
    .asFunction<
        void Function(
      Pointer<RSA>,
      Pointer<Pointer<BIGNUM>>,
      Pointer<Pointer<BIGNUM>>,
      Pointer<Pointer<BIGNUM>>,
    )>();

/// RSA_set0_key sets rsa's modulus, public exponent, and private exponent to
/// n, e, and d respectively, if non-NULL. On success, it takes ownership of
/// each argument and returns one. Otherwise, it returns zero.
///
/// d may be NULL, but n and e must either be non-NULL or already configured
/// on rsa.
///
/// It is an error to call this function after rsa has been used for a
/// cryptographic operation. Construct a new RSA object instead.
///
/// ```c
/// OPENSSL_EXPORT int RSA_set0_key(RSA *rsa, BIGNUM *n, BIGNUM *e, BIGNUM *d);
/// ```
final RSA_set0_key = lookup('RSA_set0_key')
    .lookupFunc<
        Uint32 Function(
      Pointer<RSA>,
      Pointer<BIGNUM>,
      Pointer<BIGNUM>,
      Pointer<BIGNUM>,
    )>()
    .asFunction<
        int Function(
      Pointer<RSA>,
      Pointer<BIGNUM>,
      Pointer<BIGNUM>,
      Pointer<BIGNUM>,
    )>();

/// RSA_set0_factors sets rsa's prime factors to p and q, if non-NULL, and
/// takes ownership of them. On success, it takes ownership of each argument
/// and returns one. Otherwise, it returns zero.
///
/// Each argument must either be non-NULL or already configured on rsa.
///
/// It is an error to call this function after rsa has been used for a
/// cryptographic operation. Construct a new RSA object instead.
///
/// ```c
/// OPENSSL_EXPORT int RSA_set0_factors(RSA *rsa, BIGNUM *p, BIGNUM *q);
/// ```
final RSA_set0_factors = lookup('RSA_set0_factors')
    .lookupFunc<
        Uint32 Function(
      Pointer<RSA>,
      Pointer<BIGNUM>,
      Pointer<BIGNUM>,
    )>()
    .asFunction<
        int Function(
      Pointer<RSA>,
      Pointer<BIGNUM>,
      Pointer<BIGNUM>,
    )>();

/// RSA_set0_crt_params sets rsa's CRT parameters to dmp1, dmq1, and iqmp,
/// if non-NULL, and takes ownership of them. On success, it takes ownership
/// of its parameters and returns one. Otherwise, it returns zero.
///
/// Each argument must either be non-NULL or already configured on rsa.
///
/// It is an error to call this function after rsa has been used for a
/// cryptographic operation. Construct a new RSA object instead.
///
/// ```c
/// OPENSSL_EXPORT int RSA_set0_crt_params(RSA *rsa, BIGNUM *dmp1, BIGNUM *dmq1,
///                                        BIGNUM *iqmp);
/// ```
final RSA_set0_crt_params = lookup('RSA_set0_crt_params')
    .lookupFunc<
        Uint32 Function(
      Pointer<RSA>,
      Pointer<BIGNUM>,
      Pointer<BIGNUM>,
      Pointer<BIGNUM>,
    )>()
    .asFunction<
        int Function(
      Pointer<RSA>,
      Pointer<BIGNUM>,
      Pointer<BIGNUM>,
      Pointer<BIGNUM>,
    )>();

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
/// int RSA_generate_key_ex(RSA *rsa, int bits, const BIGNUM *e,
///                                        BN_GENCB *cb);
/// ```
final RSA_generate_key_ex = lookup('RSA_generate_key_ex')
    .lookupFunc<
        Int32 Function(
      Pointer<RSA>,
      Int32,
      Pointer<BIGNUM>,
      Pointer<BN_GENCB>,
    )>()
    .asFunction<
        int Function(
      Pointer<RSA>,
      int,
      Pointer<BIGNUM>,
      Pointer<BN_GENCB>,
    )>();

//---------------------- Encryption / Decryption

/// RSA_PKCS1_PADDING denotes PKCS#1 v1.5 padding. When used with encryption,
/// this is RSAES-PKCS1-v1_5. When used with signing, this is RSASSA-PKCS1-v1_5.
///
/// ```c
/// #define RSA_PKCS1_PADDING 1
/// ```
const int RSA_PKCS1_PADDING = 1;

/// RSA_NO_PADDING denotes a raw RSA operation.
///
/// ```c
/// #define RSA_NO_PADDING 3
/// ```
const int RSA_NO_PADDING = 3;

/// RSA_PKCS1_OAEP_PADDING denotes the RSAES-OAEP encryption scheme.
///
/// ```c
/// #define RSA_PKCS1_OAEP_PADDING 4
/// ```
const int RSA_PKCS1_OAEP_PADDING = 4;

/// RSA_PKCS1_PSS_PADDING denotes the RSASSA-PSS signature scheme. This value
/// may not be passed into RSA_sign_raw, only EVP_PKEY_CTX_set_rsa_padding.
/// See also RSA_sign_pss_mgf1 and RSA_verify_pss_mgf1.
///
/// ```c
/// #define RSA_PKCS1_PSS_PADDING 6
/// ```
const int RSA_PKCS1_PSS_PADDING = 6;

//---------------------- Utility functions

/// RSA_check_key performs basic validity tests on rsa. It returns one if they
/// pass and zero otherwise. Opaque keys and public keys always pass. If it
/// returns zero then a more detailed error is available on the error queue.
///
/// ```c
/// int RSA_check_key(const RSA *rsa);
/// ```
final RSA_check_key = lookup('RSA_check_key')
    .lookupFunc<Int32 Function(Pointer<RSA>)>()
    .asFunction<int Function(Pointer<RSA>)>();

/// RSAPublicKey_dup allocates a fresh RSA and copies the public key from rsa
/// into it. It returns the fresh RSA object, or NULL on error.
///
/// ```c
/// RSA *RSAPublicKey_dup(const RSA *rsa);
/// ```
final RSAPublicKey_dup = lookup('RSAPublicKey_dup')
    .lookupFunc<Pointer<RSA> Function(Pointer<RSA>)>()
    .asFunction<Pointer<RSA> Function(Pointer<RSA>)>();
