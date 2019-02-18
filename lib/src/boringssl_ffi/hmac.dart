import 'dart:ffi';
import 'types.dart';
import 'helpers.dart';

// See:
// https://commondatastorage.googleapis.com/chromium-boringssl-docs/hmac.h.html

/// HMAC_CTX_new allocates and initialises a new HMAC_CTX and returns it, or
/// NULL on allocation failure. The caller must use HMAC_CTX_free to release
/// the resulting object.
///
/// ```c
/// OPENSSL_EXPORT HMAC_CTX *HMAC_CTX_new(void);
/// ```
final HMAC_CTX_new = lookup('HMAC_CTX_new')
    .lookupFunc<HMAC_CTX Function()>()
    .asFunction<HMAC_CTX Function()>();

/// HMAC_CTX_free calls HMAC_CTX_cleanup and then frees ctx itself.
/// ```c
/// OPENSSL_EXPORT void HMAC_CTX_free(HMAC_CTX *ctx);
/// ```
final HMAC_CTX_free = lookup('HMAC_CTX_free')
    .lookupFunc<void Function(HMAC_CTX)>()
    .asFunction<void Function(HMAC_CTX)>();

/// HMAC_Init_ex sets up an initialised HMAC_CTX to use md as the hash function
/// and key as the key. For a non-initial call, md may be NULL, in which case
/// the previous hash function will be used. If the hash function has not
/// changed and key is NULL, ctx reuses the previous key. It returns one on
/// success or zero on allocation failure.
///
/// WARNING: NULL and empty keys are ambiguous on non-initial calls. Passing
/// NULL key but repeating the previous md reuses the previous key rather than
/// the empty key.
///
/// ```c
/// OPENSSL_EXPORT int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, size_t key_len,
///                                 const EVP_MD *md, ENGINE *impl);
/// ```
final HMAC_Init_ex = lookup('HMAC_Init_ex')
    .lookupFunc<Uint32 Function(HMAC_CTX, Data, IntPtr, EVP_MD, ENGINE)>()
    .asFunction<int Function(HMAC_CTX, Data, int, EVP_MD, ENGINE)>();

/// HMAC_Update hashes data_len bytes from data into the current HMAC operation in ctx. It returns one.
/// ```c
/// OPENSSL_EXPORT int HMAC_Update(HMAC_CTX *ctx, const uint8_t *data,
///                                size_t data_len);
/// ```
final HMAC_Update = lookup('HMAC_Update')
    .lookupFunc<Uint32 Function(HMAC_CTX, Bytes, IntPtr)>()
    .asFunction<int Function(HMAC_CTX, Bytes, int)>();

/// HMAC_Final completes the HMAC operation in ctx and writes the result to out
/// and the sets *out_len to the length of the result. On entry, out must
/// contain at least HMAC_size bytes of space. An output size of EVP_MAX_MD_SIZE
/// will always be large enough. It returns one on success or zero on allocation
/// failure.
///
/// ```c
/// OPENSSL_EXPORT int HMAC_Final(HMAC_CTX *ctx, uint8_t *out,
///                               unsigned int *out_len);
/// ```
final HMAC_Final = lookup('HMAC_Final')
    .lookupFunc<Uint32 Function(HMAC_CTX, Bytes, Uint32)>()
    .asFunction<int Function(HMAC_CTX, Bytes, int)>();

/// HMAC_size returns the size, in bytes, of the HMAC that will be produced by
/// ctx. On entry, ctx must have been setup with HMAC_Init_ex.
///
/// ```c
/// OPENSSL_EXPORT size_t HMAC_size(const HMAC_CTX *ctx);
/// ```
final HMAC_size = lookup('HMAC_size')
    .lookupFunc<IntPtr Function(HMAC_CTX)>()
    .asFunction<int Function(HMAC_CTX)>();
