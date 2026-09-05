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

import 'dart:typed_data';

import 'package:webcrypto/webcrypto.dart';

import '../utils/utils.dart';

List<({String name, Future<void> Function() test})> tests() => [
  (
    name: 'RSA-OAEP SHA-1 uses the canonical JWK alg identifier',
    test: () async {
      final keyPair = await RsaOaepPrivateKey.generateKey(
        2048,
        BigInt.from(65537),
        Hash.sha1,
      );
      final privateJwk = await keyPair.privateKey.exportJsonWebKey();
      final publicJwk = await keyPair.publicKey.exportJsonWebKey();

      check(
        privateJwk['alg'] == 'RSA-OAEP',
        'Expected private JWK alg to be "RSA-OAEP"',
      );
      check(
        publicJwk['alg'] == 'RSA-OAEP',
        'Expected public JWK alg to be "RSA-OAEP"',
      );

      final privateKey = await RsaOaepPrivateKey.importJsonWebKey(
        privateJwk,
        Hash.sha1,
      );
      final publicKey = await RsaOaepPublicKey.importJsonWebKey(
        publicJwk,
        Hash.sha1,
      );
      await _checkRoundTrip(privateKey, publicKey);

      final legacyPrivateKey = await RsaOaepPrivateKey.importJsonWebKey({
        ...privateJwk,
        'alg': 'RSA-OAEP-1',
      }, Hash.sha1);
      final legacyPublicKey = await RsaOaepPublicKey.importJsonWebKey({
        ...publicJwk,
        'alg': 'RSA-OAEP-1',
      }, Hash.sha1);
      await _checkRoundTrip(legacyPrivateKey, legacyPublicKey);

      for (final (:hash, :name) in [
        (hash: Hash.sha256, name: 'SHA-256'),
        (hash: Hash.sha384, name: 'SHA-384'),
        (hash: Hash.sha512, name: 'SHA-512'),
      ]) {
        await _expectFormatException(
          () => RsaOaepPrivateKey.importJsonWebKey({
            ...privateJwk,
            'alg': 'RSA-OAEP-1',
          }, hash),
          'Expected private RSA-OAEP-1 JWK to be rejected for $name',
        );
        await _expectFormatException(
          () => RsaOaepPublicKey.importJsonWebKey({
            ...publicJwk,
            'alg': 'RSA-OAEP-1',
          }, hash),
          'Expected public RSA-OAEP-1 JWK to be rejected for $name',
        );
      }
    },
  ),
];

Future<void> _checkRoundTrip(
  RsaOaepPrivateKey privateKey,
  RsaOaepPublicKey publicKey,
) async {
  final plaintext = Uint8List.fromList([1, 2, 3, 4]);
  final ciphertext = await publicKey.encryptBytes(plaintext);
  final decrypted = await privateKey.decryptBytes(ciphertext);
  check(equalBytes(decrypted, plaintext), 'RSA-OAEP round trip failed');
}

Future<void> _expectFormatException(
  Future<Object> Function() callback,
  String message,
) async {
  var rejected = false;
  try {
    await callback();
  } on FormatException {
    rejected = true;
  }
  check(rejected, message);
}
