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
    name: 'HMAC generates a key above the random-fill quota',
    test: () async {
      const length = 65536 * 8 + 1;
      final key = await HmacSecretKey.generateKey(Hash.sha256, length: length);
      final raw = await key.exportRawKey();

      check(raw.length == 65537, 'Expected a 65537-byte generated key');
      check(raw.last & 0x7f == 0, 'Unused bits must be zero');

      final data = [1, 2, 3];
      final signature = await key.signBytes(data);
      check(
        await key.verifyBytes(signature, data),
        'Generated key should be usable for signing and verification',
      );
    },
  ),
];
