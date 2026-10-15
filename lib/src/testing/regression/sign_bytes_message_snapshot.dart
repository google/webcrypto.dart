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

Future<void> _checkMessageSnapshot(
  Future<Uint8List> Function(List<int>) sign,
  Future<bool> Function(Uint8List, List<int>) verify,
) async {
  final original = <int>[1, 2, 3];
  final data = List<int>.of(original);
  final pending = sign(data);
  data[0] ^= 1;

  final signature = await pending;
  check(
    await verify(signature, original),
    'signBytes must use the message supplied at invocation',
  );
}

List<({String name, Future<void> Function() test})> tests() => [
  (
    name: 'HMAC signBytes snapshots message',
    test: () async {
      final key = await HmacSecretKey.importRawKey(
        List<int>.filled(32, 7),
        Hash.sha256,
      );
      await _checkMessageSnapshot(key.signBytes, key.verifyBytes);
    },
  ),
  (
    name: 'RSA-PSS signBytes snapshots message',
    test: () async {
      final keys = await RsaPssPrivateKey.generateKey(
        2048,
        BigInt.from(65537),
        Hash.sha256,
      );
      await _checkMessageSnapshot(
        (data) => keys.privateKey.signBytes(data, 32),
        (signature, data) => keys.publicKey.verifyBytes(signature, data, 32),
      );
    },
  ),
  (
    name: 'RSASSA-PKCS1-v1_5 signBytes snapshots message',
    test: () async {
      final keys = await RsassaPkcs1V15PrivateKey.generateKey(
        2048,
        BigInt.from(65537),
        Hash.sha256,
      );
      await _checkMessageSnapshot(
        keys.privateKey.signBytes,
        keys.publicKey.verifyBytes,
      );
    },
  ),
  (
    name: 'ECDSA signBytes snapshots message',
    test: () async {
      final keys = await EcdsaPrivateKey.generateKey(EllipticCurve.p256);
      await _checkMessageSnapshot(
        (data) => keys.privateKey.signBytes(data, Hash.sha256),
        (signature, data) =>
            keys.publicKey.verifyBytes(signature, data, Hash.sha256),
      );
    },
  ),
];
