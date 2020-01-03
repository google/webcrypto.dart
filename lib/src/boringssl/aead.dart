import 'dart:ffi';
import 'types.dart';
import 'helpers.dart';
import 'bytestring.dart';

// See:
// https://commondatastorage.googleapis.com/chromium-boringssl-docs/aead.h.html

//---------------------- AEAD algorithms.

/// EVP_aead_aes_128_gcm is AES-128 in Galois Counter Mode.
///
/// Note: AES-GCM should only be used with 12-byte (96-bit) nonces. Although it
/// is specified to take a variable-length nonce, nonces with other lengths are
/// effectively randomized, which means one must consider collisions.
/// Unless implementing an existing protocol which has already specified
/// incorrect parameters, only use 12-byte nonces.
///
/// ```c
/// OPENSSL_EXPORT const EVP_AEAD *EVP_aead_aes_128_gcm(void);
/// ```
final EVP_aead_aes_128_gcm = lookup('EVP_aead_aes_128_gcm')
    .lookupFunc<Pointer<EVP_AEAD> Function()>()
    .asFunction<Pointer<EVP_AEAD> Function()>();

/// EVP_aead_aes_256_gcm is AES-256 in Galois Counter Mode.
///
/// Note: AES-GCM should only be used with 12-byte (96-bit) nonces. Although it
/// is specified to take a variable-length nonce, nonces with other lengths are
/// ffectively randomized, which means one must consider collisions. Unless
/// implementing an existing protocol which has already specified incorrect
/// parameters, only use 12-byte nonces.
/// ```c
/// OPENSSL_EXPORT const EVP_AEAD *EVP_aead_aes_256_gcm(void);
/// ```
final EVP_aead_aes_256_gcm = lookup('EVP_aead_aes_256_gcm')
    .lookupFunc<Pointer<EVP_AEAD> Function()>()
    .asFunction<Pointer<EVP_AEAD> Function()>();

//---------------------- Utility functions.

/// EVP_AEAD_key_length returns the length, in bytes, of the keys used by aead.
///
/// ```c
/// OPENSSL_EXPORT size_t EVP_AEAD_key_length(const EVP_AEAD *aead);
/// ```
final EVP_AEAD_key_length = lookup('EVP_AEAD_key_length')
    .lookupFunc<IntPtr Function(Pointer<EVP_AEAD>)>()
    .asFunction<int Function(Pointer<EVP_AEAD>)>();

/// EVP_AEAD_nonce_length returns the length, in bytes, of the per-message nonce
/// for aead.
///
/// ```c
/// OPENSSL_EXPORT size_t EVP_AEAD_nonce_length(const EVP_AEAD *aead);
/// ```
final EVP_AEAD_nonce_length = lookup('EVP_AEAD_nonce_length')
    .lookupFunc<IntPtr Function(Pointer<EVP_AEAD>)>()
    .asFunction<int Function(Pointer<EVP_AEAD>)>();

/// EVP_AEAD_max_overhead returns the maximum number of additional bytes added
/// by the act of sealing data with aead.
///
/// ```c
/// OPENSSL_EXPORT size_t EVP_AEAD_max_overhead(const EVP_AEAD *aead);
/// ```
final EVP_AEAD_max_overhead = lookup('EVP_AEAD_max_overhead')
    .lookupFunc<IntPtr Function(Pointer<EVP_AEAD>)>()
    .asFunction<int Function(Pointer<EVP_AEAD>)>();

/// EVP_AEAD_max_tag_len returns the maximum tag length when using aead. This is
/// the largest value that can be passed as tag_len to EVP_AEAD_CTX_init.
///
/// ```c
/// OPENSSL_EXPORT size_t EVP_AEAD_max_tag_len(const EVP_AEAD *aead);
/// ```
final EVP_AEAD_max_tag_len = lookup('EVP_AEAD_max_tag_len')
    .lookupFunc<IntPtr Function(Pointer<EVP_AEAD>)>()
    .asFunction<int Function(Pointer<EVP_AEAD>)>();

//---------------------- AEAD operations.

/// EVP_AEAD_CTX_new allocates an EVP_AEAD_CTX, calls EVP_AEAD_CTX_init and
/// returns the EVP_AEAD_CTX, or NULL on error.
///
/// ```c
/// OPENSSL_EXPORT EVP_AEAD_CTX *EVP_AEAD_CTX_new(const EVP_AEAD *aead,
///                                               const uint8_t *key,
///                                               size_t key_len, size_t tag_len);
/// ```
final EVP_AEAD_CTX_new = lookup('EVP_AEAD_CTX_new')
    .lookupFunc<
        Pointer<EVP_AEAD_CTX> Function(
      Pointer<EVP_AEAD>,
      Pointer<Bytes>,
      IntPtr,
      IntPtr,
    )>()
    .asFunction<
        Pointer<EVP_AEAD_CTX> Function(
      Pointer<EVP_AEAD>,
      Pointer<Bytes>,
      int,
      int,
    )>();

/// EVP_AEAD_CTX_free calls EVP_AEAD_CTX_cleanup and OPENSSL_free on ctx.
///
/// ```c
/// OPENSSL_EXPORT void EVP_AEAD_CTX_free(EVP_AEAD_CTX *ctx);
/// ```
final EVP_AEAD_CTX_free = lookup('EVP_AEAD_CTX_free')
    .lookupFunc<IntPtr Function(Pointer<EVP_AEAD_CTX>)>()
    .asFunction<int Function(Pointer<EVP_AEAD_CTX>)>();

/// EVP_AEAD_CTX_seal encrypts and authenticates in_len bytes from in and
/// authenticates ad_len bytes from ad and writes the result to out. It returns
/// one on success and zero otherwise.
///
/// This function may be called concurrently with itself or any other seal/open
/// function on the same EVP_AEAD_CTX.
///
/// At most max_out_len bytes are written to out and, in order to ensure
/// success, max_out_len should be in_len plus the result of
/// EVP_AEAD_max_overhead. On successful return, *out_len is set to the actual
/// number of bytes written.
///
/// The length of nonce, nonce_len, must be equal to the result of
/// EVP_AEAD_nonce_length for this AEAD.
///
/// EVP_AEAD_CTX_seal never results in a partial output. If max_out_len is
/// insufficient, zero will be returned. If any error occurs, out will be
/// filled with zero bytes and *out_len set to zero.
///
/// If in and out alias then out must be == in.
///
/// ```c
/// OPENSSL_EXPORT int EVP_AEAD_CTX_seal(const EVP_AEAD_CTX *ctx, uint8_t *out,
///                                      size_t *out_len, size_t max_out_len,
///                                      const uint8_t *nonce, size_t nonce_len,
///                                      const uint8_t *in, size_t in_len,
///                                      const uint8_t *ad, size_t ad_len);
/// ```
final EVP_AEAD_CTX_seal = lookup('EVP_AEAD_CTX_seal')
    .lookupFunc<
        Int32 Function(
      Pointer<EVP_AEAD_CTX>,
      Pointer<Bytes>,
      Pointer<IntPtr>,
      IntPtr,
      Pointer<Bytes>,
      IntPtr,
      Pointer<Bytes>,
      IntPtr,
      Pointer<Bytes>,
      IntPtr,
    )>()
    .asFunction<
        int Function(
      Pointer<EVP_AEAD_CTX>,
      Pointer<Bytes>,
      Pointer<IntPtr>,
      int,
      Pointer<Bytes>,
      int,
      Pointer<Bytes>,
      int,
      Pointer<Bytes>,
      int,
    )>();

/// EVP_AEAD_CTX_open authenticates in_len bytes from in and ad_len bytes from
/// ad and decrypts at most in_len bytes into out. It returns one on success
/// and zero otherwise.
///
/// This function may be called concurrently with itself or any other seal/open
/// function on the same EVP_AEAD_CTX.
///
/// At most in_len bytes are written to out. In order to ensure success,
/// max_out_len should be at least in_len. On successful return, *out_len is
/// set to the the actual number of bytes written.
///
/// The length of nonce, nonce_len, must be equal to the result of
/// EVP_AEAD_nonce_length for this AEAD.
///
/// EVP_AEAD_CTX_open never results in a partial output. If max_out_len is
/// insufficient, zero will be returned. If any error occurs, out will be
/// filled with zero bytes and *out_len set to zero.
///
/// If in and out alias then out must be == in.
///
/// ```c
/// OPENSSL_EXPORT int EVP_AEAD_CTX_open(const EVP_AEAD_CTX *ctx, uint8_t *out,
///                                      size_t *out_len, size_t max_out_len,
///                                      const uint8_t *nonce, size_t nonce_len,
///                                      const uint8_t *in, size_t in_len,
///                                      const uint8_t *ad, size_t ad_len);
/// ```
final EVP_AEAD_CTX_open = lookup('EVP_AEAD_CTX_open')
    .lookupFunc<
        Int32 Function(
      Pointer<EVP_AEAD_CTX>,
      Pointer<Bytes>,
      Pointer<IntPtr>,
      IntPtr,
      Pointer<Bytes>,
      IntPtr,
      Pointer<Bytes>,
      IntPtr,
      Pointer<Bytes>,
      IntPtr,
    )>()
    .asFunction<
        int Function(
      Pointer<EVP_AEAD_CTX>,
      Pointer<Bytes>,
      Pointer<IntPtr>,
      int,
      Pointer<Bytes>,
      int,
      Pointer<Bytes>,
      int,
      Pointer<Bytes>,
      int,
    )>();
