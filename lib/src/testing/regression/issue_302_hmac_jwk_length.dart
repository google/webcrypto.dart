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

List<({String name, Future<void> Function() test})> tests() {
  final tests = <({String name, Future<void> Function() test})>[];
  void test(String name, Future<void> Function() fn) =>
      tests.add((name: name, test: fn));

  test('Hmac: importJsonWebKey accepts matching length', () async {
    final keyData = [0xff, 0x80];
    final jwk = {'kty': 'oct', 'alg': 'HS256', 'k': '_4A'};

    final jwkKey = await HmacSecretKey.importJsonWebKey(
      jwk,
      Hash.sha256,
      length: 9,
    );

    check(
      equalBytes(await jwkKey.exportRawKey(), keyData),
      'JWK import should preserve key data that matches length',
    );
  });

  test('Hmac: importJsonWebKey rejects non-zero unused bits', () async {
    final jwk = {'kty': 'oct', 'alg': 'HS256', 'k': '_-A'};

    bool threw = false;
    try {
      await HmacSecretKey.importJsonWebKey(jwk, Hash.sha256, length: 9);
    } on FormatException {
      threw = true;
    }
    check(threw, 'Should throw FormatException for non-zero unused bits');
  });

  test('Hmac: importJsonWebKey validates length', () async {
    final jwk = {'kty': 'oct', 'alg': 'HS256', 'k': '_4A'};

    bool threw = false;
    try {
      await HmacSecretKey.importJsonWebKey(jwk, Hash.sha256, length: 7);
    } on FormatException {
      threw = true;
    }
    check(threw, 'Should throw FormatException for invalid HMAC key length');
  });

  return tests;
}
