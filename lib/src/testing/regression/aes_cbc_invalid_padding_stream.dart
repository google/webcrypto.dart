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
    name: 'AES-CBC decryptStream emits no plaintext with invalid padding',
    test: () async {
      final key = await AesCbcSecretKey.importRawKey(List.filled(16, 0));
      final iv = List.filled(16, 0);
      final ciphertext = await key.encryptBytes(
        List.generate(32, (i) => i),
        iv,
      );
      ciphertext[ciphertext.length - 1] ^= 1;

      final plaintext = <int>[];
      var threw = false;
      try {
        await for (final chunk in key.decryptStream(
          Stream.value(ciphertext),
          iv,
        )) {
          plaintext.addAll(chunk);
        }
      } on OperationError {
        threw = true;
      }

      check(threw, 'Expected invalid padding to throw OperationError');
      check(plaintext.isEmpty, 'Expected invalid padding to emit no plaintext');
    },
  ),
];
