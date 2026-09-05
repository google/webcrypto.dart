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

@TestOn('vm')
library;

import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';

const _lengthTooLong =
    'Length specified for HkdfSecretKey.deriveBits is too long';

void main() {
  late HkdfSecretKey key;

  setUpAll(() async {
    key = await HkdfSecretKey.importRawKey(const [1, 2, 3, 4]);
  });

  for (final (name, hash, hashLengthInBytes) in [
    ('SHA-1', Hash.sha1, 20),
    ('SHA-256', Hash.sha256, 32),
    ('SHA-384', Hash.sha384, 48),
    ('SHA-512', Hash.sha512, 64),
  ]) {
    final maxLengthInBytes = 255 * hashLengthInBytes;

    test('$name accepts the RFC 5869 maximum output length', () async {
      final derived = await key.deriveBits(
        maxLengthInBytes * 8,
        hash,
        const [],
        const [],
      );

      expect(derived, hasLength(maxLengthInBytes));
    });

    test('$name rejects output one byte beyond the maximum', () async {
      await expectLater(
        key.deriveBits((maxLengthInBytes + 1) * 8, hash, const [], const []),
        throwsA(
          isA<OperationError>().having(
            (error) => error.toString(),
            'message',
            _lengthTooLong,
          ),
        ),
      );
    });
  }

  test(
    'rejects a huge output length before allocating native memory',
    () async {
      await expectLater(
        key.deriveBits(9223372036854775800, Hash.sha256, const [], const []),
        throwsA(
          isA<OperationError>().having(
            (error) => error.toString(),
            'message',
            _lengthTooLong,
          ),
        ),
      );
    },
  );
}
