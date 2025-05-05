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

library impl_stub;

import 'dart:typed_data';
import 'dart:async';

import 'package:meta/meta.dart';

part 'impl_interface.aescbc.dart';
part 'impl_interface.aesctr.dart';
part 'impl_interface.hmac.dart';
part 'impl_interface.pbkdf2.dart';
part 'impl_interface.aesgcm.dart';
part 'impl_interface.ecdh.dart';
part 'impl_interface.ecdsa.dart';
part 'impl_interface.rsaoaep.dart';
part 'impl_interface.hkdf.dart';
part 'impl_interface.rsapss.dart';
part 'impl_interface.rsassapkcs1v15.dart';
part 'impl_interface.digest.dart';
part 'impl_interface.random.dart';

/// A key-pair as returned from key generation.
typedef KeyPair<T, S> = ({T privateKey, S publicKey});

/// Elliptic curves supported by ECDSA and ECDH.
///
/// > [!NOTE]
/// > Additional values may be added to this enum in the future.
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

/// Thrown when an operation failed for an operation-specific reason.
final class OperationError extends Error {
  final String _message;

  OperationError._(this._message); // keep the constructor private.

  @override
  String toString() => _message;
}

/// Creating an [OperationError].
@internal
OperationError operationError(String message) => OperationError._(message);

/// Interface to be provided by platform implementations.
///
/// A platform implementation of `package:webcrypto` must define a
/// constant `webCryptImpl` as follows:
/// ```dart
/// const WebCryptoImpl webCryptImpl = const _MyPlatformImplemetation();
/// ```
///
/// The only platform implementations are:
///  * `lib/src/impl_ffi/impl_ffi.dart`,
///  * `lib/src/impl_js/impl_js.dart`, and,
///  * `lib/src/impl_stub/impl_stub.dart`.
///
/// These interfaces are not public and should not be implemented
/// outside this package. Should platform implementations ever become
/// plugable these interfaces will be renamed.
abstract interface class WebCryptoImpl {
  StaticAesCbcSecretKeyImpl get aesCbcSecretKey;
  StaticAesCtrSecretKeyImpl get aesCtrSecretKey;
  StaticAesGcmSecretKeyImpl get aesGcmSecretKey;
  StaticHmacSecretKeyImpl get hmacSecretKey;
  StaticPbkdf2SecretKeyImpl get pbkdf2SecretKey;
  StaticEcdhPrivateKeyImpl get ecdhPrivateKey;
  StaticEcdhPublicKeyImpl get ecdhPublicKey;
  StaticEcdsaPrivateKeyImpl get ecdsaPrivateKey;
  StaticEcdsaPublicKeyImpl get ecdsaPublicKey;
  StaticRsaOaepPrivateKeyImpl get rsaOaepPrivateKey;
  StaticRsaOaepPublicKeyImpl get rsaOaepPublicKey;
  StaticHkdfSecretKeyImpl get hkdfSecretKey;
  StaticRsaPssPrivateKeyImpl get rsaPssPrivateKey;
  StaticRsaPssPublicKeyImpl get rsaPssPublicKey;
  StaticRsaSsaPkcs1v15PrivateKeyImpl get rsaSsaPkcs1v15PrivateKey;
  StaticRsaSsaPkcs1v15PublicKeyImpl get rsaSsaPkcs1v15PublicKey;
  HashImpl get sha1;
  HashImpl get sha256;
  HashImpl get sha384;
  HashImpl get sha512;
  RandomImpl get random;
}
