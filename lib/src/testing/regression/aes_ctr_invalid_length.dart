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

List<({String name, Future<void> Function() test})> tests() => [
  (
    name: 'AES-CTR rejects invalid counter lengths',
    test: () async {
      final key = await AesCtrSecretKey.importRawKey(List.filled(16, 0));
      final counter = List.filled(16, 0);
      const plaintext = [1, 2, 3];
      final ciphertext = await key.encryptBytes(plaintext, counter, 128);

      for (final length in [-1, 0, 129, 256]) {
        await _expectArgumentError(
          () => key.encryptBytes(plaintext, counter, length),
          length,
        );
        await _expectArgumentError(
          () => key.decryptBytes(ciphertext, counter, length),
          length,
        );
      }
    },
  ),
];

Future<void> _expectArgumentError(
  Future<Object?> Function() callback,
  int length,
) async {
  Object? error;
  try {
    await callback();
  } catch (e) {
    error = e;
  }
  check(
    error is ArgumentError,
    'Expected ArgumentError for AES-CTR length $length, got $error',
  );
}
