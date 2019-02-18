import 'dart:ffi';
import 'types.dart';
import 'helpers.dart';

// See:
// https://commondatastorage.googleapis.com/chromium-boringssl-docs/digest.h.html

/// The following functions return EVP_MD objects that implement the named
/// hash function.
///
/// ```c
/// OPENSSL_EXPORT const EVP_MD *EVP_sha1(void);
/// OPENSSL_EXPORT const EVP_MD *EVP_sha256(void);
/// OPENSSL_EXPORT const EVP_MD *EVP_sha384(void);
/// OPENSSL_EXPORT const EVP_MD *EVP_sha512(void);
/// ```
final EVP_sha1 = lookup('EVP_sha1')
        .lookupFunc<EVP_MD Function()>()
        .asFunction<EVP_MD Function()>(),
    EVP_sha256 = lookup('EVP_sha256')
        .lookupFunc<EVP_MD Function()>()
        .asFunction<EVP_MD Function()>(),
    EVP_sha384 = lookup('EVP_sha384')
        .lookupFunc<EVP_MD Function()>()
        .asFunction<EVP_MD Function()>(),
    EVP_sha512 = lookup('EVP_sha512')
        .lookupFunc<EVP_MD Function()>()
        .asFunction<EVP_MD Function()>();

/// EVP_MD_size returns the digest size of md, in bytes.
///
/// ```c
/// OPENSSL_EXPORT size_t EVP_MD_size(const EVP_MD *md);
/// ```
final EVP_MD_size = lookup('EVP_MD_size')
    .lookupFunc<IntPtr Function(EVP_MD)>()
    .asFunction<int Function(EVP_MD)>();

/// EVP_MD_CTX_new allocates and initialises a fresh EVP_MD_CTX and returns it,
/// or NULL on allocation failure. The caller must use EVP_MD_CTX_free to
/// release the resulting object.
///
/// ```c
/// OPENSSL_EXPORT EVP_MD_CTX *EVP_MD_CTX_new(void);
/// ```
final EVP_MD_CTX_new = lookup('EVP_MD_CTX_new')
    .lookupFunc<EVP_MD_CTX Function()>()
    .asFunction<EVP_MD_CTX Function()>();

/// EVP_MD_CTX_free calls EVP_MD_CTX_cleanup and then frees ctx itself.
///
/// ```c
/// OPENSSL_EXPORT void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
/// ```
final EVP_MD_CTX_free = lookup('EVP_MD_CTX_free')
    .lookupFunc<Void Function(EVP_MD_CTX)>()
    .asFunction<void Function(EVP_MD_CTX)>();

/// EVP_DigestInit acts like EVP_DigestInit_ex except that ctx is initialised
/// before use.
///
/// ```c
/// OPENSSL_EXPORT int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
/// ```
final EVP_DigestInit = lookup('EVP_DigestInit')
    .lookupFunc<Int32 Function(EVP_MD_CTX, EVP_MD)>()
    .asFunction<int Function(EVP_MD_CTX, EVP_MD)>();

/// EVP_DigestUpdate hashes len bytes from data into the hashing operation
/// in ctx. It returns one.
///
/// ```c
/// OPENSSL_EXPORT int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *data,
///                                     size_t len);
/// ```
final EVP_DigestUpdate = lookup('EVP_DigestUpdate')
    .lookupFunc<Int32 Function(EVP_MD_CTX, Data, IntPtr)>()
    .asFunction<int Function(EVP_MD_CTX, Data, int)>();

/// EVP_DigestFinal acts like EVP_DigestFinal_ex except that EVP_MD_CTX_cleanup
/// is called on ctx before returning.
///
/// ```c
/// OPENSSL_EXPORT int EVP_DigestFinal(EVP_MD_CTX *ctx, uint8_t *md_out,
///                                    unsigned int *out_size);
/// ```
final EVP_DigestFinal = lookup('EVP_DigestFinal')
    .lookupFunc<Int32 Function(EVP_MD_CTX, Bytes, Pointer<Uint32>)>()
    .asFunction<int Function(EVP_MD_CTX, Bytes, Pointer<Uint32>)>();

/// EVP_MD_CTX_size returns the digest size of ctx, in bytes. It will crash if
/// a digest hasn't been set on ctx.
///
/// ```c
/// OPENSSL_EXPORT size_t EVP_MD_CTX_size(const EVP_MD_CTX *ctx);
/// ```
final EVP_MD_CTX_size = lookup('EVP_MD_CTX_size')
    .lookupFunc<IntPtr Function(EVP_MD_CTX)>()
    .asFunction<int Function(EVP_MD_CTX)>();
