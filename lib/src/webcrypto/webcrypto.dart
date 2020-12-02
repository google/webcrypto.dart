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

library webcrypto;

import 'package:meta/meta.dart';
import 'dart:convert';
import 'dart:async';
import 'dart:typed_data';
import '../impl_stub.dart'
    if (dart.library.ffi) '../impl_ffi/impl_ffi.dart'
    if (dart.library.js) '../impl_js/impl_js.dart' as impl;

part 'webcrypto.aescbc.dart';
part 'webcrypto.aesctr.dart';
part 'webcrypto.aesgcm.dart';
part 'webcrypto.digest.dart';
part 'webcrypto.ecdh.dart';
part 'webcrypto.ecdsa.dart';
part 'webcrypto.hkdf.dart';
part 'webcrypto.hmac.dart';
part 'webcrypto.pbkdf2.dart';
part 'webcrypto.random.dart';
part 'webcrypto.rsaoaep.dart';
part 'webcrypto.rsapss.dart';
part 'webcrypto.rsassapkcs1v15.dart';

/// Thrown when an operation failed for an operation-specific reason.
@sealed
abstract class OperationError extends Error {
  OperationError._(); // keep the constructor private.
}

/// A key-pair as returned from key generation.
@sealed
abstract class KeyPair<S, T> {
  KeyPair._(); // keep the constructor private.

  /// Private key for [publicKey].
  S get privateKey;

  /// Public key matching [privateKey].
  T get publicKey;
}

/// Elliptic curves supported by ECDSA and ECDH.
///
/// **Remark**, additional values may be added to this enum in the future.
enum EllipticCurve {
  p256,
  p384,

  ///
  ///
  /// P-521 is **not supported on Safari**, see [bug 216755 (bugs.webkit.org)][1].
  ///
  /// [1]: https://bugs.webkit.org/show_bug.cgi?id=216755
  p521,
}
