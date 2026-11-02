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

import 'dart:async';

import 'package:webcrypto/webcrypto.dart';

import '../utils/utils.dart';

void main() => tests().runTests();

List<({String name, Future<void> Function() test})> tests() => [
  (
    name: 'RSASSA-PKCS1-v1_5 verification snapshots the signature',
    test: () async {
      final pair = await RsassaPkcs1V15PrivateKey.generateKey(
        1024,
        BigInt.from(65537),
        Hash.sha256,
      );
      await _checkSnapshot(
        pair.privateKey.signBytes,
        pair.publicKey.verifyStream,
        pair.publicKey.verifyBytes,
      );
    },
  ),
  (
    name: 'RSA-PSS verification snapshots the signature',
    test: () async {
      final pair = await RsaPssPrivateKey.generateKey(
        1024,
        BigInt.from(65537),
        Hash.sha256,
      );
      await _checkSnapshot(
        (data) => pair.privateKey.signBytes(data, 32),
        (signature, data) => pair.publicKey.verifyStream(signature, data, 32),
        (signature, data) => pair.publicKey.verifyBytes(signature, data, 32),
      );
    },
  ),
];

Future<void> _checkSnapshot(
  Future<List<int>> Function(List<int>) sign,
  Future<bool> Function(List<int>, Stream<List<int>>) verifyStream,
  Future<bool> Function(List<int>, List<int>) verifyBytes,
) async {
  const data = [1, 2, 3];
  final signature = await sign(data);

  for (final validAtInvocation in [true, false]) {
    final input = List<int>.of(signature);
    if (!validAtInvocation) input[0] ^= 1;

    final controller = StreamController<List<int>>();
    final pending = verifyStream(input, controller.stream);
    input[0] ^= 1;
    controller.add(data);
    await controller.close();

    check(
      await pending == validAtInvocation,
      'verification must use the signature supplied at invocation',
    );

    final bytesInput = List<int>.of(signature);
    if (!validAtInvocation) bytesInput[0] ^= 1;
    final bytesPending = verifyBytes(bytesInput, data);
    bytesInput[0] ^= 1;
    check(
      await bytesPending == validAtInvocation,
      'byte verification must use the signature supplied at invocation',
    );
  }
}
