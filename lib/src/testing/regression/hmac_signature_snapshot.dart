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

List<({String name, Future<void> Function() test})> tests() {
  final tests = <({String name, Future<void> Function() test})>[];
  void test(String name, Future<void> Function() fn) =>
      tests.add((name: name, test: fn));

  test('Hmac: verifyStream snapshots an invalid signature', () async {
    final key = await HmacSecretKey.importRawKey(
      List<int>.filled(32, 7),
      Hash.sha256,
    );
    final data = List<int>.filled(128, 3);
    final signature = await key.signBytes(data);
    signature[0] ^= 1;

    final controller = StreamController<List<int>>();
    final pending = key.verifyStream(signature, controller.stream);

    // Restore the valid bytes while verification is waiting for stream data.
    signature[0] ^= 1;
    controller.add(data);
    await controller.close();

    check(
      !await pending,
      'verification must use the invalid signature supplied at invocation',
    );
  });

  test('Hmac: verifyStream snapshots a valid signature', () async {
    final key = await HmacSecretKey.importRawKey(
      List<int>.filled(32, 7),
      Hash.sha256,
    );
    final data = List<int>.filled(128, 3);
    final signature = await key.signBytes(data);

    final controller = StreamController<List<int>>();
    final pending = key.verifyStream(signature, controller.stream);

    // Corrupt the caller-owned list while verification is waiting.
    signature[0] ^= 1;
    controller.add(data);
    await controller.close();

    check(
      await pending,
      'verification must use the valid signature supplied at invocation',
    );
  });

  test('Hmac: verifyBytes snapshots the signature at invocation', () async {
    final key = await HmacSecretKey.importRawKey(
      List<int>.filled(32, 7),
      Hash.sha256,
    );
    final data = List<int>.filled(50000, 3);
    final signature = await key.signBytes(data);
    signature[0] ^= 1;

    final pending = key.verifyBytes(signature, data);
    signature[0] ^= 1;

    check(
      !await pending,
      'verifyBytes must not observe a later signature mutation',
    );
  });

  return tests;
}
