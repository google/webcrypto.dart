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

void main() {
  group('JWK import rejects conflicting use and key_ops', () {
    test('HMAC: use=sig with key_ops=[encrypt]', () async {
      await expectLater(
        () => HmacSecretKey.importJsonWebKey(
          {
            'kty': 'oct',
            'k': 'YWJjZGVmZ2hpamtsbW5vcA',
            'use': 'sig',
            'key_ops': ['encrypt'],
          },
          Hash.sha256,
        ),
        throwsA(anything),
      );
    });

    test('AES: use=enc with key_ops=[sign]', () async {
      await expectLater(
        () => AesCbcSecretKey.importJsonWebKey(
          {
            'kty': 'oct',
            'k': 'YWJjZGVmZ2hpamtsbW5vcA',
            'use': 'enc',
            'key_ops': ['sign'],
          },
        ),
        throwsA(anything),
      );
    });

    test('ECDSA: use=sig with key_ops=[deriveBits]', () async {
      await expectLater(
        () => EcdsaPrivateKey.importJsonWebKey(
          {
            'kty': 'EC',
            'crv': 'P-256',
            'x': 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
            'y': '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
            'd': '870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE',
            'use': 'sig',
            'key_ops': ['deriveBits'],
          },
          EllipticCurve.p256,
        ),
        throwsA(anything),
      );
    });

    test('RSA: use=sig with key_ops=[encrypt,decrypt]', () async {
      await expectLater(
        () => RsaSsaPkcs1V15PrivateKey.importJsonWebKey(
          {
            'kty': 'RSA',
            'use': 'sig',
            'key_ops': ['encrypt', 'decrypt'],
          },
          Hash.sha256,
        ),
        throwsA(anything),
      );
    });
  });
}
