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
    name: 'AES-CBC encryptBytes snapshots the IV',
    test: () async {
      final key = await AesCbcSecretKey.importRawKey(List<int>.filled(16, 0));
      const plaintext = [1, 2, 3];
      final iv = List<int>.filled(16, 0);
      final pending = key.encryptBytes(plaintext, iv);
      iv[15] = 1;

      final actual = await pending;
      final expected = await key.encryptBytes(
        plaintext,
        List<int>.filled(16, 0),
      );
      check(equalBytes(actual, expected));
    },
  ),
  (
    name: 'AES-CBC decryptBytes snapshots the IV',
    test: () async {
      final key = await AesCbcSecretKey.importRawKey(List<int>.filled(16, 0));
      const plaintext = [1, 2, 3];
      final originalIv = List<int>.filled(16, 0);
      final ciphertext = await key.encryptBytes(plaintext, originalIv);
      final iv = List<int>.filled(16, 0);
      final pending = key.decryptBytes(ciphertext, iv);
      iv[0] = 1;

      check(equalBytes(await pending, plaintext));
    },
  ),
];
