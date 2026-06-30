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
import '../utils/detected_runtime.dart';
import '../utils/utils.dart';

final _cases = [
  (name: 'P-256', curve: EllipticCurve.p256, maxBits: 256),
  (name: 'P-384', curve: EllipticCurve.p384, maxBits: 384),
  (name: 'P-521', curve: EllipticCurve.p521, maxBits: 528),
];

void main() => tests().runTests();

List<({String name, Future<void> Function() test})> tests() {
  final tests = <({String name, Future<void> Function() test})>[];
  void test(String name, Future<void> Function() fn) =>
      tests.add((name: name, test: fn));

  for (final c in _cases) {
    if (detectedRuntime == 'safari' && c.curve == EllipticCurve.p521) {
      continue;
    }

    test('ECDH: ${c.name} allows maximum deriveBits length', () async {
      final aliceKeyPair = await EcdhPrivateKey.generateKey(c.curve);
      final bobKeyPair = await EcdhPrivateKey.generateKey(c.curve);

      final secret = await aliceKeyPair.privateKey.deriveBits(
        c.maxBits,
        bobKeyPair.publicKey,
      );

      check(secret.length == c.maxBits ~/ 8, 'secret length mismatch');
    });

    test('ECDH: ${c.name} rejects deriveBits larger than maximum', () async {
      final aliceKeyPair = await EcdhPrivateKey.generateKey(c.curve);
      final bobKeyPair = await EcdhPrivateKey.generateKey(c.curve);

      var threw = false;
      try {
        await aliceKeyPair.privateKey.deriveBits(
          c.maxBits + 8,
          bobKeyPair.publicKey,
        );
      } on OperationError {
        threw = true;
      }
      check(
        threw,
        'Should throw OperationError for deriveBits larger than maximum',
      );
    });
  }

  return tests;
}
