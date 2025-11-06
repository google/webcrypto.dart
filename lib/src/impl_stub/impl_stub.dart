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

library webcrypto.impl_stub;

import 'dart:typed_data';

import 'package:webcrypto/src/impl_interface/impl_interface.dart';

part 'impl_stub.aescbc.dart';
part 'impl_stub.aesctr.dart';
part 'impl_stub.aesgcm.dart';
part 'impl_stub.hmac.dart';
part 'impl_stub.pbkdf2.dart';
part 'impl_stub.ecdh.dart';
part 'impl_stub.ecdsa.dart';
part 'impl_stub.ed25519.dart';
part 'impl_stub.rsaoaep.dart';
part 'impl_stub.hkdf.dart';
part 'impl_stub.rsapss.dart';
part 'impl_stub.rsassapkcs1v15.dart';
part 'impl_stub.x25519.dart';
part 'impl_stub.digest.dart';
part 'impl_stub.random.dart';

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
  final ed25519PrivateKey = const _StaticEd25519PrivateKeyImpl();

  @override
  final ed25519PublicKey = const _StaticEd25519PublicKeyImpl();

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
  final x25519PrivateKey = const _StaticX25519PrivateKeyImpl();

  @override
  final x25519PublicKey = const _StaticX25519PublicKeyImpl();

  @override
  final sha1 = const _HashImpl();

  @override
  final sha256 = const _HashImpl();

  @override
  final sha384 = const _HashImpl();

  @override
  final sha512 = const _HashImpl();

  @override
  final random = const _RandomImpl();
}
