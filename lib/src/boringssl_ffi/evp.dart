import 'dart:ffi';
import 'types.dart';
import 'helpers.dart';
import 'bytestring.dart';

// See:
// https://commondatastorage.googleapis.com/chromium-boringssl-docs/evp.h.html

//---------------------- Public key objects.

/// EVP_PKEY_new creates a new, empty public-key object and returns it or NULL
/// on allocation failure.
///
/// ```c
/// EVP_PKEY *EVP_PKEY_new(void);
/// ```
final EVP_PKEY_new = lookup('EVP_PKEY_new')
    .lookupFunc<EVP_PKEY Function()>()
    .asFunction<EVP_PKEY Function()>();

/// EVP_PKEY_free frees all data referenced by pkey and then frees pkey itself.
///
/// ```c
/// void EVP_PKEY_free(EVP_PKEY *pkey);
/// ```
final EVP_PKEY_free = lookup('EVP_PKEY_free')
    .lookupFunc<Void Function(EVP_PKEY)>()
    .asFunction<void Function(EVP_PKEY)>();

//---------------------- Getting and setting concrete public key types

/// The following functions get and set the underlying public key in an EVP_PKEY
/// object. The set1 functions take an additional reference to the underlying
/// key and return one on success or zero if key is NULL. The assign functions
/// adopt the caller's reference and return one on success or zero if key is
/// NULL. The get1 functions return a fresh reference to the underlying object
/// or NULL if pkey is not of the correct type. The get0 functions behave the
/// same but return a non-owning pointer.
///
/// The get0 and get1 functions take const pointers and are thus non-mutating
/// for thread-safety purposes, but mutating functions on the returned
/// lower-level objects are considered to also mutate the EVP_PKEY and may not
/// be called concurrently with other operations on the EVP_PKEY.
///
/// ```c
/// int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, RSA *key);
/// int EVP_PKEY_assign_RSA(EVP_PKEY *pkey, RSA *key);
/// RSA *EVP_PKEY_get0_RSA(const EVP_PKEY *pkey);
/// RSA *EVP_PKEY_get1_RSA(const EVP_PKEY *pkey);
/// int EVP_PKEY_set1_DSA(EVP_PKEY *pkey, DSA *key);
/// int EVP_PKEY_assign_DSA(EVP_PKEY *pkey, DSA *key);
/// DSA *EVP_PKEY_get0_DSA(const EVP_PKEY *pkey);
/// DSA *EVP_PKEY_get1_DSA(const EVP_PKEY *pkey);
/// int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, EC_KEY *key);
/// int EVP_PKEY_assign_EC_KEY(EVP_PKEY *pkey, EC_KEY *key);
/// EC_KEY *EVP_PKEY_get0_EC_KEY(const EVP_PKEY *pkey);
/// EC_KEY *EVP_PKEY_get1_EC_KEY(const EVP_PKEY *pkey);
/// ```
final EVP_PKEY_set1_RSA = lookup('EVP_PKEY_set1_RSA')
    .lookupFunc<Int32 Function(EVP_PKEY, RSA)>()
    .asFunction<int Function(EVP_PKEY, RSA)>();

final EVP_PKEY_get0_RSA = lookup('EVP_PKEY_get0_RSA')
    .lookupFunc<RSA Function(EVP_PKEY)>()
    .asFunction<RSA Function(EVP_PKEY)>();

//---------------------- ASN.1 functions

/// EVP_parse_public_key decodes a DER-encoded SubjectPublicKeyInfo structure
/// (RFC 5280) from cbs and advances cbs. It returns a newly-allocated
/// EVP_PKEY or NULL on error. If the key is an EC key, the curve is guaranteed
/// to be set.
///
/// The caller must check the type of the parsed public key to ensure it is
/// suitable and validate other desired key properties such as RSA modulus
/// size or EC curve.
///
/// ```c
/// EVP_PKEY *EVP_parse_public_key(CBS *cbs);
/// ```
final EVP_parse_public_key = lookup('EVP_parse_public_key')
    .lookupFunc<EVP_PKEY Function(CBS)>()
    .asFunction<EVP_PKEY Function(CBS)>();

/// EVP_marshal_public_key marshals key as a DER-encoded SubjectPublicKeyInfo
/// structure (RFC 5280) and appends the result to cbb. It returns one on
/// success and zero on error.
///
/// ```c
/// int EVP_marshal_public_key(CBB *cbb, const EVP_PKEY *key);
/// ```
final EVP_marshal_public_key = lookup('EVP_marshal_public_key')
    .lookupFunc<Int32 Function(CBB, EVP_PKEY)>()
    .asFunction<int Function(CBB, EVP_PKEY)>();

/// EVP_parse_private_key decodes a DER-encoded PrivateKeyInfo structure
/// (RFC 5208) from cbs and advances cbs. It returns a newly-allocated EVP_PKEY
/// or NULL on error.
///
/// The caller must check the type of the parsed private key to ensure it is
/// suitable and validate other desired key properties such as RSA modulus size
/// or EC curve.
///
/// A PrivateKeyInfo ends with an optional set of attributes. These are not
/// processed and so this function will silently ignore any trailing data in
/// the structure.
///
/// ```c
/// EVP_PKEY *EVP_parse_private_key(CBS *cbs);
/// ```
final EVP_parse_private_key = lookup('EVP_parse_private_key')
    .lookupFunc<EVP_PKEY Function(CBS)>()
    .asFunction<EVP_PKEY Function(CBS)>();

/// EVP_marshal_private_key marshals key as a DER-encoded PrivateKeyInfo
/// structure (RFC 5208) and appends the result to cbb. It returns one on
/// success and zero on error.
///
/// ```c
/// int EVP_marshal_private_key(CBB *cbb, const EVP_PKEY *key);
/// ```
final EVP_marshal_private_key = lookup('EVP_marshal_private_key')
    .lookupFunc<Int32 Function(CBB, EVP_PKEY)>()
    .asFunction<int Function(CBB, EVP_PKEY)>();

//---------------------- Signing

/// EVP_DigestSignInit sets up ctx for a signing operation with type and pkey.
/// The ctx argument must have been initialised with EVP_MD_CTX_init. If pctx
/// is not NULL, the EVP_PKEY_CTX of the signing operation will be written to
/// *pctx; this can be used to set alternative signing options.
///
/// For single-shot signing algorithms which do not use a pre-hash, such as
/// Ed25519, type should be NULL. The EVP_MD_CTX itself is unused but is present
/// so the API is uniform. See EVP_DigestSign.
///
/// This function does not mutate pkey for thread-safety purposes and may be
/// used concurrently with other non-mutating functions on pkey.
///
/// It returns one on success, or zero on error.
/// ```c
/// int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
///                                       const EVP_MD *type, ENGINE *e,
///                                       EVP_PKEY *pkey);
/// ```
final EVP_DigestSignInit = lookup('EVP_DigestSignInit')
    .lookupFunc<
        Int32 Function(
      EVP_MD_CTX,
      Pointer<EVP_PKEY_CTX>,
      EVP_MD,
      ENGINE,
      EVP_PKEY,
    )>()
    .asFunction<
        int Function(
      EVP_MD_CTX,
      Pointer<EVP_PKEY_CTX>,
      EVP_MD,
      ENGINE,
      EVP_PKEY,
    )>();

/// EVP_DigestSignUpdate appends len bytes from data to the data which will be
/// signed in EVP_DigestSignFinal. It returns one.
///
/// This function performs a streaming signing operation and will fail for
/// signature algorithms which do not support this. Use EVP_DigestSign for a
/// single-shot operation.
///
/// ```c
/// int EVP_DigestSignUpdate(EVP_MD_CTX *ctx, const void *data,
///                                         size_t len);
/// ```
final EVP_DigestSignUpdate = lookup('EVP_DigestSignUpdate')
    .lookupFunc<Int32 Function(EVP_MD_CTX, Data, IntPtr)>()
    .asFunction<int Function(EVP_MD_CTX, Data, int)>();

/// EVP_DigestSignFinal signs the data that has been included by one or more
/// calls to EVP_DigestSignUpdate. If out_sig is NULL then *out_sig_len is set
/// to the maximum number of output bytes. Otherwise, on entry, *out_sig_len
/// must contain the length of the out_sig buffer. If the call is successful,
/// the signature is written to out_sig and *out_sig_len is set to its length.
///
/// This function performs a streaming signing operation and will fail for
/// signature algorithms which do not support this. Use EVP_DigestSign for a
/// single-shot operation.
///
/// It returns one on success, or zero on error.
///
/// ```c
/// int EVP_DigestSignFinal(EVP_MD_CTX *ctx, uint8_t *out_sig,
///                                        size_t *out_sig_len);
/// ```
final EVP_DigestSignFinal = lookup('EVP_DigestSignFinal')
    .lookupFunc<Int32 Function(EVP_MD_CTX, Bytes, Pointer<IntPtr>)>()
    .asFunction<int Function(EVP_MD_CTX, Bytes, Pointer<IntPtr>)>();

//---------------------- Verifying

/// EVP_DigestVerifyInit sets up ctx for a signature verification operation
/// with type and pkey. The ctx argument must have been initialised with
/// EVP_MD_CTX_init. If pctx is not NULL, the EVP_PKEY_CTX of the signing
/// operation will be written to *pctx; this can be used to set alternative
/// signing options.
///
/// For single-shot signing algorithms which do not use a pre-hash, such as
/// Ed25519, type should be NULL. The EVP_MD_CTX itself is unused but is present
/// so the API is uniform. See EVP_DigestVerify.
///
/// This function does not mutate pkey for thread-safety purposes and may be
/// used concurrently with other non-mutating functions on pkey.
///
/// It returns one on success, or zero on error.
///
/// ```c
/// int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
///                                         const EVP_MD *type, ENGINE *e,
///                                         EVP_PKEY *pkey);
/// ```
final EVP_DigestVerifyInit = lookup('EVP_DigestVerifyInit')
    .lookupFunc<
        Int32 Function(
      EVP_MD_CTX,
      Pointer<EVP_PKEY_CTX>,
      EVP_MD,
      ENGINE,
      EVP_PKEY,
    )>()
    .asFunction<
        int Function(
      EVP_MD_CTX,
      Pointer<EVP_PKEY_CTX>,
      EVP_MD,
      ENGINE,
      EVP_PKEY,
    )>();

/// EVP_DigestVerifyUpdate appends len bytes from data to the data which will be
/// verified by EVP_DigestVerifyFinal. It returns one.
///
/// This function performs streaming signature verification and will fail for
/// signature algorithms which do not support this. Use EVP_PKEY_verify_message
/// for a single-shot verification.
///
/// ```c
/// int EVP_DigestVerifyUpdate(EVP_MD_CTX *ctx, const void *data,
///                                           size_t len);
/// ```
final EVP_DigestVerifyUpdate = lookup('EVP_DigestVerifyUpdate')
    .lookupFunc<Int32 Function(EVP_MD_CTX, Data, IntPtr)>()
    .asFunction<int Function(EVP_MD_CTX, Data, int)>();

/// EVP_DigestVerifyFinal verifies that sig_len bytes of sig are a valid
/// signature for the data that has been included by one or more calls to
/// EVP_DigestVerifyUpdate. It returns one on success and zero otherwise.
///
/// This function performs streaming signature verification and will fail for
/// signature algorithms which do not support this. Use EVP_PKEY_verify_message
/// for a single-shot verification.
///
/// ```c
/// int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const uint8_t *sig,
///                                          size_t sig_len);
/// ```
final EVP_DigestVerifyFinal = lookup('EVP_DigestVerifyFinal')
    .lookupFunc<Int32 Function(EVP_MD_CTX, Bytes, IntPtr)>()
    .asFunction<int Function(EVP_MD_CTX, Bytes, int)>();
