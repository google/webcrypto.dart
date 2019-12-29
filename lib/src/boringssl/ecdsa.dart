import 'dart:ffi';
import 'types.dart';
import 'helpers.dart';
import 'bytestring.dart';

// See:
// https://commondatastorage.googleapis.com/chromium-boringssl-docs/ecdsa.h.html

//---------------------- Low-level signing and verification.

/// ECDSA_SIG_new returns a fresh ECDSA_SIG structure or NULL on error.
///
/// ```c
/// OPENSSL_EXPORT ECDSA_SIG *ECDSA_SIG_new(void);
/// ```
final ECDSA_SIG_new = lookup('ECDSA_SIG_new')
    .lookupFunc<Pointer<ECDSA_SIG> Function()>()
    .asFunction<Pointer<ECDSA_SIG> Function()>();

/// ECDSA_SIG_free frees sig its member BIGNUMs.
///
/// ```c
/// OPENSSL_EXPORT void ECDSA_SIG_free(ECDSA_SIG *sig);
/// ```
final ECDSA_SIG_free = lookup('ECDSA_SIG_free')
    .lookupFunc<Void Function(Pointer<ECDSA_SIG>)>()
    .asFunction<void Function(Pointer<ECDSA_SIG>)>();

/// ECDSA_SIG_get0 sets *out_r and *out_s, if non-NULL, to the two components
/// of sig.
///
/// ```c
/// OPENSSL_EXPORT void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **out_r,
///                                    const BIGNUM **out_s);
/// ```
final ECDSA_SIG_get0 = lookup('ECDSA_SIG_get0')
    .lookupFunc<
        Void Function(Pointer<ECDSA_SIG>, Pointer<Pointer<BIGNUM>>,
            Pointer<Pointer<BIGNUM>>)>()
    .asFunction<
        void Function(Pointer<ECDSA_SIG>, Pointer<Pointer<BIGNUM>>,
            Pointer<Pointer<BIGNUM>>)>();

//---------------------- ASN.1 functions.

/// ECDSA_SIG_parse parses a DER-encoded ECDSA-Sig-Value structure from cbs and advances cbs. It returns a newly-allocated ECDSA_SIG or NULL on error.
///
/// ```c
/// OPENSSL_EXPORT ECDSA_SIG *ECDSA_SIG_parse(CBS *cbs);
/// ```
final ECDSA_SIG_parse = lookup('ECDSA_SIG_parse')
    .lookupFunc<Pointer<ECDSA_SIG> Function(Pointer<CBS>)>()
    .asFunction<Pointer<ECDSA_SIG> Function(Pointer<CBS>)>();

/// ECDSA_SIG_marshal marshals sig as a DER-encoded ECDSA-Sig-Value and appends
/// the result to cbb. It returns one on success and zero on error.
///
/// ```c
/// OPENSSL_EXPORT int ECDSA_SIG_marshal(CBB *cbb, const ECDSA_SIG *sig);
/// ```
final ECDSA_SIG_marshal = lookup('ECDSA_SIG_marshal')
    .lookupFunc<Int32 Function(Pointer<CBB>, Pointer<ECDSA_SIG>)>()
    .asFunction<int Function(Pointer<CBB>, Pointer<ECDSA_SIG>)>();
