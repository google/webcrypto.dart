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
import 'package:webcrypto/src/crypto_subtle.dart' as subtle;
import 'package:webcrypto/src/impl_js/impl_js.dart';

void main() {
  group('fillRandomBytes', () {
    test('Uint8List: success', () {
      final data = Uint8List(16 * 1024);
      expect(
        data.every((e) => e == 0),
        isTrue,
      );
      fillRandomBytes(data);
      expect(
        data.any((e) => e != 0),
        isTrue,
      );
    });

    test('Uint8List: too long', () {
      expect(
        () => fillRandomBytes(Uint8List(1000000)),
        throwsA(
          isA<ArgumentError>(),
        ),
      );
    });

    test('Uint64List: not supported type', () {
      expect(
        () => fillRandomBytes(Uint64List(32)),
        throwsA(
          isA<UnsupportedError>(),
        ),
      );
    });
  });

  group('crypto', () {
    test('getRandomValues: success', () {
      final data = Uint8List(16 * 1024);
      expect(
        data.every((e) => e == 0),
        isTrue,
      );
      subtle.window.crypto.getRandomValues(data.toJS);
      expect(
        data.any((e) => e != 0),
        isTrue,
      );
    });

    test('getRandomValues: too long', () {
      expect(
        () => subtle.window.crypto.getRandomValues(Uint8List(1000000).toJS),
        throwsA(
          isA<subtle.JSDomException>().having(
            (e) => e.name,
            'name',
            'QuotaExceededError',
          ),
        ),
      );
    });

    test('getRandomValues: not supported type', () {
      expect(
        () => subtle.window.crypto.getRandomValues(Float32List(32).toJS),
        throwsA(
          isA<subtle.JSDomException>().having(
            (e) => e.name,
            'name',
            'TypeMismatchError',
          ),
        ),
      );
    });
  });

  group('crypto.subtle', () {
    test('generateCryptoKey: success', () async {
      expect(
        await subtle.window.crypto.subtle
            .generateCryptoKey(
              const subtle.Algorithm(
                name: 'AES-GCM',
                length: 256,
              ).toJS,
              false,
              ['encrypt', 'decrypt'].toJS,
            )
            .toDart,
        isA<subtle.JSCryptoKey>()
            .having(
              (key) => key.type,
              'type',
              'secret',
            )
            .having(
              (key) => key.extractable,
              'extractable',
              false,
            )
            .having(
              (key) => key.usages,
              'usages',
              containsAll(['encrypt', 'decrypt']),
            ),
      );
    });

    test('generateCryptoKey: invalid keyUsages', () {
      expect(
        () async => await subtle.window.crypto.subtle
            .generateCryptoKey(
              const subtle.Algorithm(
                name: 'AES-GCM',
                length: 256,
              ).toJS,
              false,
              <String>[].toJS,
            )
            .toDart,
        throwsA(
          isA<subtle.JSDomException>().having(
            (e) => e.name,
            'name',
            'SyntaxError',
          ),
        ),
      );
    });

    test('generateCryptoKey: invalid algorithm', () {
      expect(
        () async => await subtle.window.crypto.subtle
            .generateCryptoKey(
              const subtle.Algorithm().toJS,
              false,
              ['encrypt', 'decrypt'].toJS,
            )
            .toDart,
        throwsA(
          isA<subtle.JSDomException>().having(
            (e) => e.name,
            'name',
            // Chrome / Safari throw TypeError
            // Firefox throws SyntaxError
            anyOf('TypeError', 'SyntaxError'),
          ),
        ),
      );
    });

    test('generateKeyPair: e65537', () async {
      expect(
        await subtle.window.crypto.subtle
            .generateCryptoKeyPair(
              subtle.Algorithm(
                name: 'RSA-OAEP',
                modulusLength: 4096,
                publicExponent: Uint8List.fromList([0x01, 0x00, 0x01]),
                hash: 'SHA-256',
              ).toJS,
              false,
              ['encrypt', 'decrypt'].toJS,
            )
            .toDart,
        isA<subtle.JSCryptoKeyPair>()
            .having(
              (key) => key.publicKey.type,
              'publicKey.type',
              'public',
            )
            .having(
              (key) => key.publicKey.extractable,
              'publicKey.extractable',
              true,
            )
            .having(
              (key) => key.publicKey.usages,
              'publicKey.usages',
              ['encrypt'],
            )
            .having(
              (key) => key.privateKey.type,
              'privateKey.type',
              'private',
            )
            .having(
              (key) => key.privateKey.extractable,
              'privateKey.extractable',
              false,
            )
            .having(
              (key) => key.privateKey.usages,
              'privateKey.usages',
              ['decrypt'],
            ),
      );
    });

    test(testOn: 'chrome || firefox', 'generateKeyPair: e3', () async {
      expect(
        await subtle.window.crypto.subtle
            .generateCryptoKeyPair(
              subtle.Algorithm(
                name: 'RSA-OAEP',
                modulusLength: 4096,
                publicExponent: Uint8List.fromList([0x03]),
                hash: 'SHA-256',
              ).toJS,
              false,
              ['encrypt', 'decrypt'].toJS,
            )
            .toDart,
        isA<subtle.JSCryptoKeyPair>()
            .having(
              (key) => key.publicKey.type,
              'publicKey.type',
              'public',
            )
            .having(
              (key) => key.publicKey.extractable,
              'publicKey.extractable',
              true,
            )
            .having(
              (key) => key.publicKey.usages,
              'publicKey.usages',
              ['encrypt'],
            )
            .having(
              (key) => key.privateKey.type,
              'privateKey.type',
              'private',
            )
            .having(
              (key) => key.privateKey.extractable,
              'privateKey.extractable',
              false,
            )
            .having(
              (key) => key.privateKey.usages,
              'privateKey.usages',
              ['decrypt'],
            ),
      );
    });

    test(testOn: 'safari', 'generateKeyPair: e3', () {
      expect(
        () async => await subtle.window.crypto.subtle
            .generateCryptoKeyPair(
              subtle.Algorithm(
                name: 'RSA-OAEP',
                modulusLength: 4096,
                publicExponent: Uint8List.fromList([0x03]),
                hash: 'SHA-256',
              ).toJS,
              false,
              ['encrypt', 'decrypt'].toJS,
            )
            .toDart,
        throwsA(
          isA<subtle.JSDomException>().having(
            (e) => e.name,
            'name',
            'OperationError',
          ),
        ),
      );
    });
  });
}
