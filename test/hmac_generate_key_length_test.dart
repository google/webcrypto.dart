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

import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';

void main() {
  for (final length in [0x100000000, 9007199254740992]) {
    test(
      'rejects out-of-range HMAC key length $length before allocation',
      () async {
        await expectLater(
          HmacSecretKey.generateKey(Hash.sha256, length: length),
          throwsA(
            isA<ArgumentError>().having(
              (error) => error.invalidValue,
              'invalidValue',
              length,
            ),
          ),
        );
      },
    );
  }
}
