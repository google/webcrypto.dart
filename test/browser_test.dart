@TestOn('browser')
// Copyright 2024 Google LLC
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

import 'dart:js_interop';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webcrypto/src/impl_js/impl_js.dart';
import 'package:webcrypto/src/crypto_subtle.dart';
import 'package:webcrypto/src/testing/webcrypto/random.dart';

void main() {
  group('fillRandomBytes', () {
    test('Uint8List: success', () {
      final data = Uint8List(16 * 1024);
      isAllZero(data);
      fillRandomBytes(data);
      isNotAllZero(data);
    });

    test('Uint8List: too long', () {
      expect(
        () => fillRandomBytes(Uint8List(1000000)),
        throwsA(isA<ArgumentError>().having(
          (e) => e.message,
          'message',
          contains(
            '''Failed to execute 'getRandomValues' on 'Crypto': The ArrayBufferView's byte length (1000000) exceeds the number of bytes of entropy available via this API (65536).''',
          ),
        )),
      );
    });

    test('Uint64List: not supported type', () {
      expect(
        () => fillRandomBytes(Uint64List(32)),
        throwsA(
          isA<UnsupportedError>().having(
            (e) => e.message,
            'message',
            contains(
              'Uint64List not supported on the web.',
            ),
          ),
        ),
      );
    });
  });

  group('crypto.subtle', () {
    test('generateCryptoKey: success', () async {
      final key = await window.crypto.subtle
          .generateCryptoKey(
            const Algorithm(
              name: 'ECDH',
              namedCurve: 'P-384',
            ).toJS,
            false,
            ['deriveBits'].toJS,
          )
          .toDart;

      expect(key, isA<JSCryptoKey>());
    });

    test('generateCryptoKey: SyntaxError', () async {
      expect(
        () async => await window.crypto.subtle
            .generateCryptoKey(
              const Algorithm(
                name: 'ECDH',
                namedCurve: 'P-384',
              ).toJS,
              false,
              <String>[].toJS,
            )
            .toDart,
        throwsA(
          isA<JSDomException>()
              .having(
                (e) => e.name,
                'name',
                'SyntaxError',
              )
              .having(
                (e) => e.message,
                'message',
                contains(
                  '''Usages cannot be empty when creating a key''',
                ),
              ),
        ),
      );
    });

    test('generateCryptoKey: TypeError', () async {
      expect(
        () async => await window.crypto.subtle
            .generateCryptoKey(
              const Algorithm().toJS,
              false,
              ['deriveBits'].toJS,
            )
            .toDart,
        throwsA(
          isA<JSDomException>()
              .having(
                (e) => e.name,
                'name',
                'TypeError',
              )
              .having(
                (e) => e.message,
                'message',
                contains(
                  '''Failed to execute 'generateKey' on 'SubtleCrypto': Algorithm: name: Missing or not a string''',
                ),
              ),
        ),
      );
    });
  });
}
