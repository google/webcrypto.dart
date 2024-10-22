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

import 'package:webcrypto/webcrypto.dart' show Hash;

part 'impl_interface.aescbc.dart';
part 'impl_interface.aesctr.dart';
part 'impl_interface.hmac.dart';
part 'impl_interface.pbkdf2.dart';
part 'impl_interface.aesgcm.dart';
part 'impl_interface.ecdh.dart';
part 'impl_interface.ecdsa.dart';
part 'impl_interface.rsaoaep.dart';

/// A key-pair as returned from key generation.
class KeyPair<S, T> {
  KeyPair._(this.privateKey, this.publicKey); // keep the constructor private.

  /// Private key for [publicKey].
  final S privateKey;

  /// Public key matching [privateKey].
  final T publicKey;
}

/// Factory method to create KeyPair instance
KeyPair<S, T> createKeyPair<S, T>(S privateKey, T publicKey) {
  return KeyPair._(privateKey, publicKey);
}

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
}
