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

final _rsaPrivateJwkImporters =
    <String, Future<void> Function(Map<String, dynamic>)>{
      'RSA-OAEP': (jwk) async {
        await RsaOaepPrivateKey.importJsonWebKey(jwk, Hash.sha256);
      },
      'RSA-PSS': (jwk) async {
        await RsaPssPrivateKey.importJsonWebKey(jwk, Hash.sha256);
      },
      'RSASSA-PKCS1-v1_5': (jwk) async {
        await RsassaPkcs1V15PrivateKey.importJsonWebKey(jwk, Hash.sha256);
      },
    };

Future<Map<String, dynamic>> _generateRsaPrivateJwk() async {
  final keys = await RsaOaepPrivateKey.generateKey(
    1024,
    BigInt.from(65537),
    Hash.sha256,
  );
  final jwk = await keys.privateKey.exportJsonWebKey();
  jwk.remove('alg');
  jwk.remove('use');
  return jwk;
}

List<({String name, Future<void> Function() test})> tests() => [
  for (final MapEntry(key: algorithm, value: importKey)
      in _rsaPrivateJwkImporters.entries)
    (
      name: '$algorithm rejects unsupported RSA other primes',
      test: () async {
        final jwk = await _generateRsaPrivateJwk();
        await importKey(jwk);

        for (final oth in [
          <Map<String, String>>[],
          [
            {'r': 'Aw', 'd': 'AQ', 't': 'AQ'},
          ],
        ]) {
          Object? error;
          try {
            await importKey({...jwk, 'oth': oth});
          } catch (e) {
            error = e;
          }
          check(
            error is FormatException,
            'Expected FormatException for JWK with "oth", got $error',
          );
        }
      },
    ),
];
