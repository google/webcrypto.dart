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

  return tests;
}
