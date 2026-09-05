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

List<({String name, Future<void> Function() test})> tests() => [
  (
    name: 'AES-GCM rejects out-of-range tag lengths',
    test: () async {
      final key = await AesGcmSecretKey.importRawKey(List.filled(16, 0));
      final iv = List.generate(12, (i) => i);
      const plaintext = [1, 2, 3];
      final ciphertext = await key.encryptBytes(plaintext, iv);

      for (final tagLength in [-128, 384]) {
        await _expectOperationError(
          () => key.encryptBytes(plaintext, iv, tagLength: tagLength),
          'Expected encryption with tagLength $tagLength to be rejected',
        );
        await _expectOperationError(
          () => key.decryptBytes(ciphertext, iv, tagLength: tagLength),
          'Expected decryption with tagLength $tagLength to be rejected',
        );
      }
    },
  ),
];

Future<void> _expectOperationError(
  Future<Object?> Function() callback,
  String message,
) async {
  try {
    await callback();
  } on OperationError {
    return;
  }
  check(false, message);
}
