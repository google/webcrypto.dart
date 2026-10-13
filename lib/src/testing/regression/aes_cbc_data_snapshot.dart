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
    name: 'AES-CBC encryptBytes snapshots plaintext',
    test: () async {
      final key = await AesCbcSecretKey.importRawKey(List<int>.filled(16, 0));
      final iv = List<int>.filled(16, 1);
      final plaintext = List<int>.filled(32, 2);
      final expected = await key.encryptBytes(List<int>.of(plaintext), iv);

      final pending = key.encryptBytes(plaintext, iv);
      plaintext.fillRange(0, plaintext.length, 3);

      check(equalBytes(await pending, expected));
    },
  ),
  (
    name: 'AES-CBC decryptBytes snapshots ciphertext',
    test: () async {
      final key = await AesCbcSecretKey.importRawKey(List<int>.filled(16, 0));
      final iv = List<int>.filled(16, 1);
      final plaintext = List<int>.filled(32, 2);
      final ciphertext = await key.encryptBytes(plaintext, iv);

      final pending = key.decryptBytes(ciphertext, iv);
      ciphertext[0] ^= 1;

      check(equalBytes(await pending, plaintext));
    },
  ),
];
