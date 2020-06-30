// ignore_for_file: non_constant_identifier_names

/// This library maps symbols from:
/// https://commondatastorage.googleapis.com/chromium-boringssl-docs/cipher.h.html
library cipher;

import 'dart:ffi';
import 'types.dart';
import 'lookup/lookup.dart';

//---------------------- Cipher primitives.

/// The following functions return EVP_CIPHER objects that implement the named
/// cipher algorithm.
///
/// ```c
/// OPENSSL_EXPORT const EVP_CIPHER *EVP_rc4(void);
/// OPENSSL_EXPORT const EVP_CIPHER *EVP_des_cbc(void);
/// OPENSSL_EXPORT const EVP_CIPHER *EVP_des_ecb(void);
/// OPENSSL_EXPORT const EVP_CIPHER *EVP_des_ede(void);
/// OPENSSL_EXPORT const EVP_CIPHER *EVP_des_ede3(void);
/// OPENSSL_EXPORT const EVP_CIPHER *EVP_des_ede_cbc(void);
/// OPENSSL_EXPORT const EVP_CIPHER *EVP_des_ede3_cbc(void);
/// OPENSSL_EXPORT const EVP_CIPHER *EVP_aes_128_ecb(void);
/// OPENSSL_EXPORT const EVP_CIPHER *EVP_aes_128_cbc(void);
/// OPENSSL_EXPORT const EVP_CIPHER *EVP_aes_128_ctr(void);
/// OPENSSL_EXPORT const EVP_CIPHER *EVP_aes_128_ofb(void);
/// OPENSSL_EXPORT const EVP_CIPHER *EVP_aes_256_ecb(void);
/// OPENSSL_EXPORT const EVP_CIPHER *EVP_aes_256_cbc(void);
/// OPENSSL_EXPORT const EVP_CIPHER *EVP_aes_256_ctr(void);
/// OPENSSL_EXPORT const EVP_CIPHER *EVP_aes_256_ofb(void);
/// OPENSSL_EXPORT const EVP_CIPHER *EVP_aes_256_xts(void);
/// ```
final EVP_aes_128_cbc = resolve(Sym.EVP_aes_128_cbc)
    .lookupFunc<Pointer<EVP_CIPHER> Function()>()
    .asFunction<Pointer<EVP_CIPHER> Function()>();
final EVP_aes_128_ctr = resolve(Sym.EVP_aes_128_ctr)
    .lookupFunc<Pointer<EVP_CIPHER> Function()>()
    .asFunction<Pointer<EVP_CIPHER> Function()>();
final EVP_aes_256_cbc = resolve(Sym.EVP_aes_256_cbc)
    .lookupFunc<Pointer<EVP_CIPHER> Function()>()
    .asFunction<Pointer<EVP_CIPHER> Function()>();
final EVP_aes_256_ctr = resolve(Sym.EVP_aes_256_ctr)
    .lookupFunc<Pointer<EVP_CIPHER> Function()>()
    .asFunction<Pointer<EVP_CIPHER> Function()>();

//---------------------- Cipher context allocation.

/// EVP_CIPHER_CTX_new allocates a fresh EVP_CIPHER_CTX, calls
/// EVP_CIPHER_CTX_init and returns it, or NULL on allocation failure.
///
/// ```c
/// OPENSSL_EXPORT EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
/// ```
final EVP_CIPHER_CTX_new = resolve(Sym.EVP_CIPHER_CTX_new)
    .lookupFunc<Pointer<EVP_CIPHER_CTX> Function()>()
    .asFunction<Pointer<EVP_CIPHER_CTX> Function()>();

/// EVP_CIPHER_CTX_free calls EVP_CIPHER_CTX_cleanup on ctx and then frees ctx itself.
///
/// ```c
/// OPENSSL_EXPORT void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
/// ```
final EVP_CIPHER_CTX_free = resolve(Sym.EVP_CIPHER_CTX_free)
    .lookupFunc<Void Function(Pointer<EVP_CIPHER_CTX>)>()
    .asFunction<void Function(Pointer<EVP_CIPHER_CTX>)>();

//---------------------- Cipher context configuration.

/// EVP_CipherInit_ex configures ctx for a fresh encryption (or decryption,
/// if enc is zero) operation using cipher. If ctx has been previously
/// configured with a cipher then cipher, key and iv may be NULL and enc may
/// be -1 to reuse the previous values. The operation will use key as the key
/// and iv as the IV (if any). These should have the correct lengths given by
/// EVP_CIPHER_key_length and EVP_CIPHER_iv_length. It returns one on success
/// and zero on error.
///
/// ```c
/// OPENSSL_EXPORT int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,
///                                      const EVP_CIPHER *cipher, ENGINE *engine,
///                                      const uint8_t *key, const uint8_t *iv,
///                                      int enc);
/// ```
final EVP_CipherInit_ex = resolve(Sym.EVP_CipherInit_ex)
    .lookupFunc<
        Int32 Function(
      Pointer<EVP_CIPHER_CTX>,
      Pointer<EVP_CIPHER>,
      Pointer<ENGINE>,
      Pointer<Bytes>,
      Pointer<Bytes>,
      Int32,
    )>()
    .asFunction<
        int Function(
      Pointer<EVP_CIPHER_CTX>,
      Pointer<EVP_CIPHER>,
      Pointer<ENGINE>,
      Pointer<Bytes>,
      Pointer<Bytes>,
      int,
    )>();

//---------------------- Cipher context configuration.

/// EVP_CipherUpdate calls either EVP_EncryptUpdate or EVP_DecryptUpdate
/// depending on how ctx has been setup.
///
/// ```c
/// OPENSSL_EXPORT int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, uint8_t *out,
///                                     int *out_len, const uint8_t *in,
///                                     int in_len);
/// ```
final EVP_CipherUpdate = resolve(Sym.EVP_CipherUpdate)
    .lookupFunc<
        Int32 Function(
      Pointer<EVP_CIPHER_CTX>,
      Pointer<Bytes>,
      Pointer<Int32>,
      Pointer<Bytes>,
      Int32,
    )>()
    .asFunction<
        int Function(
      Pointer<EVP_CIPHER_CTX>,
      Pointer<Bytes>,
      Pointer<Int32>,
      Pointer<Bytes>,
      int,
    )>();

/// EVP_CipherFinal_ex calls either EVP_EncryptFinal_ex or EVP_DecryptFinal_ex
/// depending on how ctx has been setup.
///
/// ```c
/// OPENSSL_EXPORT int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, uint8_t *out,
///                                       int *out_len);
/// ```
final EVP_CipherFinal_ex = resolve(Sym.EVP_CipherFinal_ex)
    .lookupFunc<
        Int32 Function(
      Pointer<EVP_CIPHER_CTX>,
      Pointer<Bytes>,
      Pointer<Int32>,
    )>()
    .asFunction<
        int Function(
      Pointer<EVP_CIPHER_CTX>,
      Pointer<Bytes>,
      Pointer<Int32>,
    )>();

//---------------------- Cipher operations.

/// EVP_CIPHER_block_size returns the block size, in bytes, for cipher, or one
/// if cipher is a stream cipher.
///
/// ```c
/// OPENSSL_EXPORT unsigned EVP_CIPHER_block_size(const EVP_CIPHER *cipher);
/// ```
final EVP_CIPHER_block_size = resolve(Sym.EVP_CIPHER_block_size)
    .lookupFunc<Uint32 Function(Pointer<EVP_CIPHER>)>()
    .asFunction<int Function(Pointer<EVP_CIPHER>)>();

/// EVP_CIPHER_iv_length returns the IV size, in bytes, of cipher, or zero if
/// cipher doesn't take an IV.
///
/// ```c
/// OPENSSL_EXPORT unsigned EVP_CIPHER_iv_length(const EVP_CIPHER *cipher);
/// ```
final EVP_CIPHER_iv_length = resolve(Sym.EVP_CIPHER_iv_length)
    .lookupFunc<Uint32 Function(Pointer<EVP_CIPHER>)>()
    .asFunction<int Function(Pointer<EVP_CIPHER>)>();
