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

library impl_js;

import 'dart:async';
import 'dart:typed_data';

import 'package:webcrypto/src/impl_interface/impl_interface.dart';

import '../webcrypto/webcrypto.dart';
import '../crypto_subtle.dart' as subtle;

part 'impl_js.aescbc.dart';
part 'impl_js.aesctr.dart';
part 'impl_js.aesgcm.dart';
part 'impl_js.digest.dart';
part 'impl_js.ecdh.dart';
part 'impl_js.ecdsa.dart';
part 'impl_js.hkdf.dart';
part 'impl_js.hmac.dart';
part 'impl_js.pbkdf2.dart';
part 'impl_js.random.dart';
part 'impl_js.rsaoaep.dart';
part 'impl_js.rsapss.dart';
part 'impl_js.rsassapkcs1v15.dart';
part 'impl_js.utils.dart';

/// Implementation of [OperationError].
class _OperationError extends Error implements OperationError {
  final String _message;
  _OperationError(this._message);
  @override
  String toString() => _message;
}

const WebCryptoImpl webCryptImpl = _WebCryptoImpl();

final class _WebCryptoImpl implements WebCryptoImpl {
  const _WebCryptoImpl();

  @override
  final aesCbcSecretKey = const _StaticAesCbcSecretKeyImpl();

  @override
  final aesCtrSecretKey = const _StaticAesCtrSecretKeyImpl();

  @override
  final aesGcmSecretKey = const _StaticAesGcmSecretKeyImpl();

  @override
  final hmacSecretKey = const _StaticHmacSecretKeyImpl();

  @override
  final pbkdf2SecretKey = const _StaticPbkdf2SecretKeyImpl();

  @override
  final ecdhPrivateKey = const _StaticEcdhPrivateKeyImpl();

  @override
  final ecdhPublicKey = const _StaticEcdhPublicKeyImpl();

  @override
  final ecdsaPrivateKey = const _StaticEcdsaPrivateKeyImpl();

  @override
  final ecdsaPublicKey = const _StaticEcdsaPublicKeyImpl();

  @override
  final rsaOaepPrivateKey = const _StaticRsaOaepPrivateKeyImpl();

  @override
  final rsaOaepPublicKey = const _StaticRsaOaepPublicKeyImpl();

  @override
  final hkdfSecretKey = const _StaticHkdfSecretKeyImpl();

  @override
  final rsaPssPrivateKey = const _StaticRsaPssPrivateKeyImpl();

  @override
  final rsaPssPublicKey = const _StaticRsaPssPublicKeyImpl();

  @override
  final rsaSsaPkcs1v15PrivateKey = const _StaticRsaSsaPkcs1V15PrivateKeyImpl();

  @override
  final rsaSsaPkcs1v15PublicKey = const _StaticRsaSsaPkcs1V15PublicKeyImpl();

  @override
  final sha1 = const _HashImpl('SHA-1');

  @override
  final sha256 = const _HashImpl('SHA-256');

  @override
  final sha384 = const _HashImpl('SHA-384');

  @override
  final sha512 = const _HashImpl('SHA-512');
}
