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

import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';

final _throwsInvalidJwk = throwsA(
  anyOf(isA<FormatException>(), isA<ArgumentError>()),
);

void main() {
  late Map<String, dynamic> privateJwk;

  setUpAll(() async {
    final pair = await RsaOaepPrivateKey.generateKey(
      1024,
      BigInt.from(65537),
      Hash.sha256,
    );
    privateJwk = await pair.privateKey.exportJsonWebKey();
  });

  test('RSA-OAEP public import rejects a private JWK', () async {
    await expectLater(
      RsaOaepPublicKey.importJsonWebKey(privateJwk, Hash.sha256),
      _throwsInvalidJwk,
    );
  });

  test('RSA-PSS public import rejects a private JWK', () async {
    await expectLater(
      RsaPssPublicKey.importJsonWebKey({
        ...privateJwk,
        'alg': 'PS256',
        'use': 'sig',
      }, Hash.sha256),
      _throwsInvalidJwk,
    );
  });

  test('RSASSA-PKCS1-v1_5 public import rejects a private JWK', () async {
    await expectLater(
      RsassaPkcs1V15PublicKey.importJsonWebKey({
        ...privateJwk,
        'alg': 'RS256',
        'use': 'sig',
      }, Hash.sha256),
      _throwsInvalidJwk,
    );
  });
}
