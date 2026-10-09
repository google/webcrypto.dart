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
  for (final ivLength in [15, 17])
    (
      name: 'AES-CBC rejects IVs with $ivLength bytes',
      test: () async {
        final key = await AesCbcSecretKey.importRawKey(List.filled(16, 0));
        const plaintext = [1, 2, 3];
        final ciphertext = await key.encryptBytes(
          plaintext,
          List.filled(16, 0),
        );
        final iv = List.filled(ivLength, 0);

        await _expectOperationError(
          () => key.encryptBytes(plaintext, iv),
          'Expected encryption with a $ivLength-byte IV to be rejected',
        );
        await _expectOperationError(
          () => key.decryptBytes(ciphertext, iv),
          'Expected decryption with a $ivLength-byte IV to be rejected',
        );
        await _expectOperationError(
          () => key.encryptStream(Stream.value(plaintext), iv).drain(),
          'Expected stream encryption with a $ivLength-byte IV to be rejected',
        );
        await _expectOperationError(
          () => key.decryptStream(Stream.value(ciphertext), iv).drain(),
          'Expected stream decryption with a $ivLength-byte IV to be rejected',
        );
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
