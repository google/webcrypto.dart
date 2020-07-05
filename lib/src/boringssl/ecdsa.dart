// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// ignore_for_file: non_constant_identifier_names

/// This library maps symbols from:
/// https://commondatastorage.googleapis.com/chromium-boringssl-docs/ecdsa.h.html
library ecdsa;

import 'dart:ffi';
import 'types.dart';
import 'lookup/lookup.dart';
import 'bytestring.dart';

//---------------------- Low-level signing and verification.

/// ECDSA_SIG_new returns a fresh ECDSA_SIG structure or NULL on error.
///
/// ```c
/// OPENSSL_EXPORT ECDSA_SIG *ECDSA_SIG_new(void);
/// ```
final ECDSA_SIG_new = resolve(Sym.ECDSA_SIG_new)
    .lookupFunc<Pointer<ECDSA_SIG> Function()>()
    .asFunction<Pointer<ECDSA_SIG> Function()>();

/// ECDSA_SIG_free frees sig its member BIGNUMs.
///
/// ```c
/// OPENSSL_EXPORT void ECDSA_SIG_free(ECDSA_SIG *sig);
/// ```
final ECDSA_SIG_free = resolve(Sym.ECDSA_SIG_free)
    .lookupFunc<Void Function(Pointer<ECDSA_SIG>)>()
    .asFunction<void Function(Pointer<ECDSA_SIG>)>();

/// ECDSA_SIG_get0 sets *out_r and *out_s, if non-NULL, to the two components
/// of sig.
///
/// ```c
/// OPENSSL_EXPORT void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **out_r,
///                                    const BIGNUM **out_s);
/// ```
final ECDSA_SIG_get0 = resolve(Sym.ECDSA_SIG_get0)
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
final ECDSA_SIG_parse = resolve(Sym.ECDSA_SIG_parse)
    .lookupFunc<Pointer<ECDSA_SIG> Function(Pointer<CBS>)>()
    .asFunction<Pointer<ECDSA_SIG> Function(Pointer<CBS>)>();

/// ECDSA_SIG_marshal marshals sig as a DER-encoded ECDSA-Sig-Value and appends
/// the result to cbb. It returns one on success and zero on error.
///
/// ```c
/// OPENSSL_EXPORT int ECDSA_SIG_marshal(CBB *cbb, const ECDSA_SIG *sig);
/// ```
final ECDSA_SIG_marshal = resolve(Sym.ECDSA_SIG_marshal)
    .lookupFunc<Int32 Function(Pointer<CBB>, Pointer<ECDSA_SIG>)>()
    .asFunction<int Function(Pointer<CBB>, Pointer<ECDSA_SIG>)>();
