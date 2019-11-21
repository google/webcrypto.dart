import 'dart:ffi';
import 'types.dart';
import 'helpers.dart';

// See:
// https://commondatastorage.googleapis.com/chromium-boringssl-docs/bn.h.html

// On 64bit we have.
// #define BN_ULONG uint64_t
// TODO: Solve BN_ULONG having a different size on other platforms.

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
