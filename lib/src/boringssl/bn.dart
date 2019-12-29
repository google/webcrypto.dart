import 'dart:ffi';
import 'types.dart';
import 'helpers.dart';

// See:
// https://commondatastorage.googleapis.com/chromium-boringssl-docs/bn.h.html

// On 64bit we have.
// #define BN_ULONG uint64_t
// TODO: Solve BN_ULONG having a different size on other platforms.

//---------------------- Allocation and freeing.

/// BN_new creates a new, allocated BIGNUM and initialises it.
///
/// ```c
/// BIGNUM *BN_new(void);
/// ```
final BN_new = lookup('BN_new')
    .lookupFunc<Pointer<BIGNUM> Function()>()
    .asFunction<Pointer<BIGNUM> Function()>();

/// BN_free frees the data referenced by bn and, if bn was originally allocated
/// on the heap, frees bn also.
///
/// ```c
/// void BN_free(BIGNUM *bn);
/// ```
final BN_free = lookup('BN_free')
    .lookupFunc<Void Function(Pointer<BIGNUM>)>()
    .asFunction<void Function(Pointer<BIGNUM>)>();

//---------------------- Basic functions.

/// BN_num_bytes returns the minimum number of bytes needed to represent the absolute value of bn.
///
/// ```c
/// OPENSSL_EXPORT unsigned BN_num_bytes(const BIGNUM *bn);
/// ```
final BN_num_bytes = lookup('BN_num_bytes')
    .lookupFunc<Uint32 Function(Pointer<BIGNUM>)>()
    .asFunction<int Function(Pointer<BIGNUM>)>();

/// BN_set_word sets bn to value. It returns one on success or zero on
/// allocation failure.
///
/// ```c
/// int BN_set_word(BIGNUM *bn, BN_ULONG value);
/// ```
final BN_set_word = lookup('BN_set_word')
    .lookupFunc<Int32 Function(Pointer<BIGNUM>, Uint64)>()
    .asFunction<int Function(Pointer<BIGNUM>, int)>();
// TODO: Solve that int doesn't match Uint64, probably need to try BigInt

//---------------------- Conversion functions.

/// BN_bin2bn sets *ret to the value of len bytes from in, interpreted as a
/// big-endian number, and returns ret. If ret is NULL then a fresh BIGNUM is
/// allocated and returned. It returns NULL on allocation failure.
///
/// ```c
/// OPENSSL_EXPORT BIGNUM *BN_bin2bn(const uint8_t *in, size_t len, BIGNUM *ret);
/// ```
final BN_bin2bn = lookup('BN_bin2bn')
    .lookupFunc<
        Pointer<BIGNUM> Function(Pointer<Bytes>, IntPtr, Pointer<BIGNUM>)>()
    .asFunction<
        Pointer<BIGNUM> Function(Pointer<Bytes>, int, Pointer<BIGNUM>)>();

/// BN_bn2bin_padded serialises the absolute value of in to out as a big-endian
/// integer. The integer is padded with leading zeros up to size len. If len is
/// smaller than BN_num_bytes, the function fails and returns 0.
/// Otherwise,it returns 1.
///
/// ```c
/// OPENSSL_EXPORT int BN_bn2bin_padded(uint8_t *out, size_t len, const BIGNUM *in);
/// ```
final BN_bn2bin_padded = lookup('BN_bn2bin_padded')
    .lookupFunc<Int32 Function(Pointer<Bytes>, IntPtr, Pointer<BIGNUM>)>()
    .asFunction<int Function(Pointer<Bytes>, int, Pointer<BIGNUM>)>();
