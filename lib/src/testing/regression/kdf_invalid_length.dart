// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'package:webcrypto/webcrypto.dart';

import '../utils/utils.dart';

List<({String name, Future<void> Function() test})> tests() => [
  (
    name: 'PBKDF2 rejects lengths outside the Web IDL unsigned long range',
    test: () async {
      final key = await Pbkdf2SecretKey.importRawKey([1]);
      for (final length in [-0xfffffff8, 0x100000008]) {
        await _expectArgumentError(key.deriveBits(length, Hash.sha256, [2], 1));
      }
    },
  ),
  (
    name: 'HKDF rejects lengths outside the Web IDL unsigned long range',
    test: () async {
      final key = await HkdfSecretKey.importRawKey([1]);
      for (final length in [-0xfffffff8, 0x100000008]) {
        await _expectArgumentError(
          key.deriveBits(length, Hash.sha256, [2], [3]),
        );
      }
    },
  ),
];

Future<void> _expectArgumentError(Future<List<int>> operation) async {
  var threw = false;
  try {
    await operation;
  } on ArgumentError {
    threw = true;
  }
  check(threw, 'Expected ArgumentError for invalid deriveBits length');
}
