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

import 'package:webcrypto/src/jsonwebkey.dart';
import 'package:webcrypto/webcrypto.dart';
import '../utils/utils.dart';

void main() => tests().runTests();

List<({String name, Future<void> Function() test})> tests() {
  final tests = <({String name, Future<void> Function() test})>[];
  void test(String name, Future<void> Function() fn) =>
      tests.add((name: name, test: fn));

  test('JsonWebKey: rejects enc use with sign/verify key_ops', () async {
    bool threw = false;
    try {
      JsonWebKey.fromJson({
        'kty': 'RSA',
        'use': 'enc',
        'key_ops': ['sign'],
        'n': 'x',
        'e': 'x',
      });
    } on FormatException {
      threw = true;
    }
    check(threw, 'enc use conflicts with sign operation');
  });

  test('JsonWebKey: rejects sig use with encrypt/decrypt key_ops', () async {
    bool threw = false;
    try {
      JsonWebKey.fromJson({
        'kty': 'RSA',
        'use': 'sig',
        'key_ops': ['encrypt'],
        'n': 'x',
        'e': 'x',
      });
    } on FormatException {
      threw = true;
    }
    check(threw, 'sig use conflicts with encrypt operation');
  });

  test('JsonWebKey: accepts valid use with matching key_ops', () async {
    // enc use with encrypt/decrypt operations
    JsonWebKey.fromJson({
      'kty': 'RSA',
      'use': 'enc',
      'key_ops': ['encrypt', 'decrypt'],
      'n': 'x',
      'e': 'x',
    });

    // sig use with sign/verify operations
    JsonWebKey.fromJson({
      'kty': 'RSA',
      'use': 'sig',
      'key_ops': ['sign', 'verify'],
      'n': 'x',
      'e': 'x',
    });
  });

  test('JsonWebKey: ignores unknown use values', () async {
    JsonWebKey.fromJson({
      'kty': 'RSA',
      'use': 'unknown',
      'key_ops': ['sign', 'encrypt'],
      'n': 'x',
      'e': 'x',
    });
  });

  test('AES-GCM JWK rejects signing use in every backend', () async {
    final jwk = {
      'kty': 'oct',
      'k': 'AAAAAAAAAAAAAAAAAAAAAA',
      'alg': 'A128GCM',
      'use': 'sig',
    };
    bool threw = false;
    try {
      await AesGcmSecretKey.importJsonWebKey(jwk);
    } on FormatException {
      threw = true;
    }
    check(threw, 'AES-GCM must reject signing use');
  });

  test('AES-GCM JWK accepts matching use and key_ops', () async {
    final key = await AesGcmSecretKey.importJsonWebKey({
      'kty': 'oct',
      'k': 'AAAAAAAAAAAAAAAAAAAAAA',
      'alg': 'A128GCM',
      'use': 'enc',
      'key_ops': ['encrypt', 'decrypt'],
    });
    check((await key.exportRawKey()).length == 16, 'valid AES-GCM JWK');
  });

  test('AES-GCM JWK rejects conflicting key_ops in every backend', () async {
    final jwk = {
      'kty': 'oct',
      'k': 'AAAAAAAAAAAAAAAAAAAAAA',
      'alg': 'A128GCM',
      'use': 'enc',
      'key_ops': ['sign'],
    };
    bool threw = false;
    try {
      await AesGcmSecretKey.importJsonWebKey(jwk);
    } on FormatException {
      threw = true;
    }
    check(threw, 'AES-GCM must reject conflicting key_ops');
  });

  test('ECDH public JWK rejects signing use in every backend', () async {
    final pair = await EcdhPrivateKey.generateKey(EllipticCurve.p256);
    final jwk = await pair.publicKey.exportJsonWebKey();
    jwk['use'] = 'sig';
    bool threw = false;
    try {
      await EcdhPublicKey.importJsonWebKey(jwk, EllipticCurve.p256);
    } on FormatException {
      threw = true;
    }
    check(threw, 'ECDH public key must reject signing use');
  });

  test(
    'ECDH private JWK accepts derivation key_ops with encryption use',
    () async {
      final pair = await EcdhPrivateKey.generateKey(EllipticCurve.p256);
      final jwk = await pair.privateKey.exportJsonWebKey();
      jwk['use'] = 'enc';
      jwk['key_ops'] = ['deriveBits'];
      final imported = await EcdhPrivateKey.importJsonWebKey(
        jwk,
        EllipticCurve.p256,
      );
      final bits = await imported.deriveBits(8, pair.publicKey);
      check(bits.length == 1, 'valid ECDH derivation JWK');
    },
  );

  return tests;
}
