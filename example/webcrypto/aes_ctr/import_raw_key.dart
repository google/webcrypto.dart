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

// ignore_for_file: avoid_print

// #region example
import 'dart:convert' show utf8;
import 'dart:typed_data' show Uint8List;

import 'package:webcrypto/webcrypto.dart';

Future<void> main() async {
  final rawKey = Uint8List(16);
  fillRandomBytes(rawKey);

  // Import key from raw bytes
  final k = await AesCtrSecretKey.importRawKey(rawKey);

  // Use a unique counter for each message.
  final ctr = Uint8List(16); // always 16 bytes
  fillRandomBytes(ctr);

  // Length of the counter, the N'th right most bits of ctr are incremented
  // for each block, the left most 128 - N bits are used as static nonce.
  final N = 64;

  // Encrypt a message
  final c = await k.encryptBytes(utf8.encode('hello world'), ctr, N);

  // Decrypt message (requires the same counter ctr and length N)
  print(utf8.decode(await k.decryptBytes(c, ctr, N))); // hello world
}

// #endregion
