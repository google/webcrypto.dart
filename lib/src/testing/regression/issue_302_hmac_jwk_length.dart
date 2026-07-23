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

  test('Hmac: importJsonWebKey applies length like importRawKey', () async {
    final keyData = [0xff, 0xe0];
    final jwk = {'kty': 'oct', 'alg': 'HS256', 'k': '_-A'};

    final rawKey = await HmacSecretKey.importRawKey(
      keyData,
      Hash.sha256,
      length: 9,
    );
    final jwkKey = await HmacSecretKey.importJsonWebKey(
      jwk,
      Hash.sha256,
      length: 9,
    );

    check(
      equalBytes(await rawKey.exportRawKey(), await jwkKey.exportRawKey()),
      'JWK import should zero unused bits the same way as raw import',
    );

    final data = [1, 2, 3, 4];
    check(
      equalBytes(await rawKey.signBytes(data), await jwkKey.signBytes(data)),
      'JWK import should use the requested HMAC key length for signing',
    );
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
