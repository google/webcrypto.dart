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

void main() => tests().runTests();

/// Tests for issue #60, exported for use in `../testing.dart`.
List<({String name, Future<void> Function() test})> tests() {
  final tests = <({String name, Future<void> Function() test})>[];
  void test(String name, Future<void> Function() testFn) =>
      tests.add((name: name, test: testFn));

  test('Ecdsa: importPkcs8Key with trailing bytes throws FormatException', () async {
    final kp = await EcdsaPrivateKey.generateKey(EllipticCurve.p256);
    final validKey = await kp.privateKey.exportPkcs8Key();
    final invalidKey = Uint8List.fromList([...validKey, 0]);

    bool threw = false;
    try {
      await EcdsaPrivateKey.importPkcs8Key(invalidKey, EllipticCurve.p256);
    } on FormatException {
      threw = true;
    }
    check(threw, 'Expected FormatException when importing EC private key with trailing bytes');
  });

  test('Ecdsa: importSpkiKey with trailing bytes throws FormatException', () async {
    final kp = await EcdsaPrivateKey.generateKey(EllipticCurve.p256);
    final validKey = await kp.publicKey.exportSpkiKey();
    final invalidKey = Uint8List.fromList([...validKey, 0]);

    bool threw = false;
    try {
      await EcdsaPublicKey.importSpkiKey(invalidKey, EllipticCurve.p256);
    } on FormatException {
      threw = true;
    }
    check(threw, 'Expected FormatException when importing EC public key with trailing bytes');
  });

  test('RsaPss: importPkcs8Key with trailing bytes throws FormatException', () async {
    final kp = await RsaPssPrivateKey.generateKey(2048, BigInt.from(65537), Hash.sha256);
    final validKey = await kp.privateKey.exportPkcs8Key();
    final invalidKey = Uint8List.fromList([...validKey, 0]);

    bool threw = false;
    try {
      await RsaPssPrivateKey.importPkcs8Key(invalidKey, Hash.sha256);
    } on FormatException {
      threw = true;
    }
    check(threw, 'Expected FormatException when importing RSA private key with trailing bytes');
  });

  test('RsaPss: importSpkiKey with trailing bytes throws FormatException', () async {
    final kp = await RsaPssPrivateKey.generateKey(2048, BigInt.from(65537), Hash.sha256);
    final validKey = await kp.publicKey.exportSpkiKey();
    final invalidKey = Uint8List.fromList([...validKey, 0]);

    bool threw = false;
    try {
      await RsaPssPublicKey.importSpkiKey(invalidKey, Hash.sha256);
    } on FormatException {
      threw = true;
    }
    check(threw, 'Expected FormatException when importing RSA public key with trailing bytes');
  });

  return tests;
}
