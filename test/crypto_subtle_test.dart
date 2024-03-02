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

    test(testOn: 'chrome', 'Uint8List: too long', () {
      expect(
        () => fillRandomBytes(Uint8List(1000000)),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            "Failed to execute 'getRandomValues' on 'Crypto': The ArrayBufferView's byte length (1000000) exceeds the number of bytes of entropy available via this API (65536).",
          ),
        ),
      );
    });

    test(testOn: 'firefox', 'Uint8List: too long', () {
      expect(
        () => fillRandomBytes(Uint8List(1000000)),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            'Crypto.getRandomValues: getRandomValues can only generate maximum 65536 bytes',
          ),
        ),
      );
    });

    test(testOn: 'safari', 'Uint8List: too long', () {
      expect(
        () => fillRandomBytes(Uint8List(1000000)),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            'The quota has been exceeded.',
          ),
        ),
      );
    });

    test('Uint64List: not supported type', () {
      expect(
        () => fillRandomBytes(Uint64List(32)),
        throwsA(
          isA<UnsupportedError>().having(
            (e) => e.message,
            'message',
            'Uint64List not supported on the web.',
          ),
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

    test(testOn: 'chrome', 'getRandomValues: too long', () {
      expect(
        () => subtle.window.crypto.getRandomValues(Uint8List(1000000).toJS),
        throwsA(
          isA<subtle.JSDomException>()
              .having(
                (e) => e.name,
                'name',
                'QuotaExceededError',
              )
              .having(
                (e) => e.message,
                'message',
                "Failed to execute 'getRandomValues' on 'Crypto': The ArrayBufferView's byte length (1000000) exceeds the number of bytes of entropy available via this API (65536).",
              ),
        ),
      );
    });

    test(testOn: 'firefox', 'getRandomValues: too long', () {
      expect(
        () => subtle.window.crypto.getRandomValues(Uint8List(1000000).toJS),
        throwsA(
          isA<subtle.JSDomException>()
              .having(
                (e) => e.name,
                'name',
                'QuotaExceededError',
              )
              .having(
                (e) => e.message,
                'message',
                'Crypto.getRandomValues: getRandomValues can only generate maximum 65536 bytes',
              ),
        ),
      );
    });

    test(testOn: 'safari', 'getRandomValues: too long', () {
      expect(
        () => subtle.window.crypto.getRandomValues(Uint8List(1000000).toJS),
        throwsA(
          isA<subtle.JSDomException>()
              .having(
                (e) => e.name,
                'name',
                'QuotaExceededError',
              )
              .having(
                (e) => e.message,
                'message',
                'The quota has been exceeded.',
              ),
        ),
      );
    });

    test(testOn: 'chrome', 'getRandomValues: not supported type', () {
      expect(
        () => subtle.window.crypto.getRandomValues(Float32List(32).toJS),
        throwsA(
          isA<subtle.JSDomException>()
              .having(
                (e) => e.name,
                'name',
                'TypeMismatchError',
              )
              .having(
                (e) => e.message,
                'message',
                "Failed to execute 'getRandomValues' on 'Crypto': The provided ArrayBufferView is of type 'Float32', which is not an integer array type.",
              ),
        ),
      );
    });

    test(testOn: 'firefox', 'getRandomValues: not supported type', () {
      expect(
        () => subtle.window.crypto.getRandomValues(Float32List(32).toJS),
        throwsA(
          isA<subtle.JSDomException>()
              .having(
                (e) => e.name,
                'name',
                'TypeMismatchError',
              )
              .having(
                (e) => e.message,
                'message',
                'The type of an object is incompatible with the expected type of the parameter associated to the object',
              ),
        ),
      );
    });

    test(testOn: 'safari', 'getRandomValues: not supported type', () {
      expect(
        () => subtle.window.crypto.getRandomValues(Float32List(32).toJS),
        throwsA(
          isA<subtle.JSDomException>()
              .having(
                (e) => e.name,
                'name',
                'TypeMismatchError',
              )
              .having(
                (e) => e.message,
                'message',
                'The type of an object was incompatible with the expected type of the parameter associated to the object.',
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

    test(testOn: 'chrome', 'generateCryptoKey: invalid keyUsages', () {
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
          isA<subtle.JSDomException>()
              .having(
                (e) => e.name,
                'name',
                'SyntaxError',
              )
              .having(
                (e) => e.message,
                'message',
                'Usages cannot be empty when creating a key.',
              ),
        ),
      );
    });

    test(testOn: 'firefox', 'generateCryptoKey: invalid keyUsages', () {
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
          isA<subtle.JSDomException>()
              .having(
                (e) => e.name,
                'name',
                'SyntaxError',
              )
              .having(
                (e) => e.message,
                'message',
                'An invalid or illegal string was specified',
              ),
        ),
      );
    });

    test(testOn: 'safari', 'generateCryptoKey: invalid keyUsages', () {
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
          isA<subtle.JSDomException>()
              .having(
                (e) => e.name,
                'name',
                'SyntaxError',
              )
              .having(
                (e) => e.message,
                'message',
                'A required parameter was missing or out-of-range',
              ),
        ),
      );
    });

    test(testOn: 'chrome', 'generateCryptoKey: invalid algorithm', () {
      expect(
        () async => await subtle.window.crypto.subtle
            .generateCryptoKey(
              const subtle.Algorithm().toJS,
              false,
              ['encrypt', 'decrypt'].toJS,
            )
            .toDart,
        throwsA(
          isA<subtle.JSDomException>()
              .having(
                (e) => e.name,
                'name',
                'TypeError',
              )
              .having(
                (e) => e.message,
                'message',
                "Failed to execute 'generateKey' on 'SubtleCrypto': Algorithm: name: Missing or not a string",
              ),
        ),
      );
    });

    test(testOn: 'firefox', 'generateCryptoKey: invalid algorithm', () {
      expect(
        () async => await subtle.window.crypto.subtle
            .generateCryptoKey(
              const subtle.Algorithm().toJS,
              false,
              ['encrypt', 'decrypt'].toJS,
            )
            .toDart,
        throwsA(
          isA<subtle.JSDomException>()
              .having(
                (e) => e.name,
                'name',
                'SyntaxError',
              )
              .having(
                (e) => e.message,
                'message',
                'An invalid or illegal string was specified',
              ),
        ),
      );
    });

    test(testOn: 'safari', 'generateCryptoKey: invalid algorithm', () {
      expect(
        () async => await subtle.window.crypto.subtle
            .generateCryptoKey(
              const subtle.Algorithm().toJS,
              false,
              ['encrypt', 'decrypt'].toJS,
            )
            .toDart,
        throwsA(
          isA<subtle.JSDomException>()
              .having(
                (e) => e.name,
                'name',
                'TypeError',
              )
              .having(
                (e) => e.message,
                'message',
                'Member CryptoAlgorithmParameters.name is required and must be an instance of DOMString',
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
          isA<subtle.JSDomException>()
              .having(
                (e) => e.name,
                'name',
                'OperationError',
              )
              .having(
                (e) => e.message,
                'message',
                'The operation failed for an operation-specific reason',
              ),
        ),
      );
    });
  });
}
