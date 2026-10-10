// Copyright 2026 Google LLC
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

import 'package:webcrypto/webcrypto.dart';

import '../utils/utils.dart';

void main() => tests().runTests();

List<({String name, Future<void> Function() test})> tests() => [
  (
    name: 'JWK exports include consistent use metadata',
    test: () async {
      final aesKeyData = List<int>.filled(16, 0);
      await _expectUse(
        (await AesCbcSecretKey.importRawKey(aesKeyData)).exportJsonWebKey(),
        'enc',
        'AES-CBC',
      );
      await _expectUse(
        (await AesCtrSecretKey.importRawKey(aesKeyData)).exportJsonWebKey(),
        'enc',
        'AES-CTR',
      );
      await _expectUse(
        (await AesGcmSecretKey.importRawKey(aesKeyData)).exportJsonWebKey(),
        'enc',
        'AES-GCM',
      );
      await _expectUse(
        (await HmacSecretKey.importRawKey(
          List<int>.filled(32, 0),
          Hash.sha256,
        )).exportJsonWebKey(),
        'sig',
        'HMAC',
      );

      final ecdsaKeyPair = await EcdsaPrivateKey.generateKey(
        EllipticCurve.p256,
      );
      await _expectUse(
        ecdsaKeyPair.privateKey.exportJsonWebKey(),
        'sig',
        'ECDSA private key',
      );
      await _expectUse(
        ecdsaKeyPair.publicKey.exportJsonWebKey(),
        'sig',
        'ECDSA public key',
      );

      final ecdhKeyPair = await EcdhPrivateKey.generateKey(EllipticCurve.p256);
      await _expectUse(
        ecdhKeyPair.privateKey.exportJsonWebKey(),
        null,
        'ECDH private key',
      );
      await _expectUse(
        ecdhKeyPair.publicKey.exportJsonWebKey(),
        null,
        'ECDH public key',
      );

      final rsaOaepKeyPair = await RsaOaepPrivateKey.generateKey(
        2048,
        BigInt.from(65537),
        Hash.sha256,
      );
      await _expectUse(
        rsaOaepKeyPair.privateKey.exportJsonWebKey(),
        'enc',
        'RSA-OAEP private key',
      );
      await _expectUse(
        rsaOaepKeyPair.publicKey.exportJsonWebKey(),
        'enc',
        'RSA-OAEP public key',
      );

      final pkcs8 = await rsaOaepKeyPair.privateKey.exportPkcs8Key();
      final spki = await rsaOaepKeyPair.publicKey.exportSpkiKey();
      final rsaPssPrivateKey = await RsaPssPrivateKey.importPkcs8Key(
        pkcs8,
        Hash.sha256,
      );
      final rsaPssPublicKey = await RsaPssPublicKey.importSpkiKey(
        spki,
        Hash.sha256,
      );
      await _expectUse(
        rsaPssPrivateKey.exportJsonWebKey(),
        'sig',
        'RSA-PSS private key',
      );
      await _expectUse(
        rsaPssPublicKey.exportJsonWebKey(),
        'sig',
        'RSA-PSS public key',
      );

      final rsaSsaPrivateKey = await RsassaPkcs1V15PrivateKey.importPkcs8Key(
        pkcs8,
        Hash.sha256,
      );
      final rsaSsaPublicKey = await RsassaPkcs1V15PublicKey.importSpkiKey(
        spki,
        Hash.sha256,
      );
      await _expectUse(
        rsaSsaPrivateKey.exportJsonWebKey(),
        'sig',
        'RSASSA-PKCS1-v1_5 private key',
      );
      await _expectUse(
        rsaSsaPublicKey.exportJsonWebKey(),
        'sig',
        'RSASSA-PKCS1-v1_5 public key',
      );
    },
  ),
];

Future<void> _expectUse(
  Future<Map<String, dynamic>> jwk,
  String? expectedUse,
  String keyType,
) async {
  final value = await jwk;
  if (expectedUse == null) {
    check(!value.containsKey('use'), 'Expected $keyType to omit JWK use');
  } else {
    check(
      value['use'] == expectedUse,
      'Expected $keyType JWK use to be "$expectedUse"',
    );
  }
}
