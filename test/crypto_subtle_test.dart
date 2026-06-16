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

@TestOn('browser')
library;

import 'dart:js_interop';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webcrypto/src/crypto_subtle.dart' as subtle;
import 'package:webcrypto/src/impl_js/impl_js.dart';
import 'package:webcrypto/webcrypto.dart';

// Cannot import `package:flutter/foundation.dart` because it depends on `dart:ui`. Define it independently for testing.
const bool kIsWasm = bool.fromEnvironment('dart.tool.dart2wasm');

void main() {
  // TODO: Test subtle.window.crypto.getRandomValues(values); instead
  group('fillRandomBytes', () {
    test('success', () {
      final list = [
        Uint8List(16 * 1024),
        Uint16List(16 * 1024),
        Uint32List(16 * 1024),
        Int8List(16 * 1024),
        Int16List(16 * 1024),
        Int32List(16 * 1024),
      ];
      for (final data in list) {
        expect(data.every((e) => e == 0), isTrue);
        fillRandomBytes(data);
        expect(data.any((e) => e != 0), isTrue);
      }
    });

    test('too long', () {
      final list = [
        Uint8List(1000000),
        Uint16List(1000000),
        Uint32List(1000000),
        Int8List(1000000),
        Int16List(1000000),
        Int32List(1000000),
      ];
      for (final data in list) {
        expect(
          // TODO: Test subtle.window.crypto.getRandomValues(values); instead
          () => fillRandomBytes(data),
          throwsA(
            // dart2js throws ArgumentError
            // dart2wasm throws UnknownError
            anyOf(isA<ArgumentError>(), isA<UnknownError>()),
          ),
        );
      }
    });

    test('not supported type', () {
      final list = [Float32List(32), Float64List(32)];
      for (final data in list) {
        expect(
          // TODO: Test subtle.window.crypto.getRandomValues(values); instead
          () => fillRandomBytes(data),
          throwsA(isA<ArgumentError>()),
        );
      }
    });

    test('list that is supported depending on the environment', () {
      if (kIsWasm) {
        final list = [Uint64List(32), Int64List(32)];

        for (final data in list) {
          expect(
            // TODO: Test subtle.window.crypto.getRandomValues(values); instead
            () => fillRandomBytes(data),
            throwsA(
              // dart2wasm throws ArgumentError in fillRandomBytes method
              isA<ArgumentError>(),
            ),
          );
        }
      } else {
        try {
          final _ = [Uint64List(32), Int64List(32)];
          fail('dart2js does not reach this line');
        } catch (e) {
          // dart2js throws UnsupportedError in list creation
          expect(e, isA<UnsupportedError>());
        }
      }
    });
  });

  group('randomUUID', () {
    test('returns a valid version 4 UUID', () {
      final uuid = randomUUID();
      expect(uuid, isA<String>());
      // Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
      expect(uuid.length, 36);
      expect(uuid[14], '4');
      expect('89ab'.contains(uuid[19]), isTrue);
      final parts = uuid.split('-');
      expect(parts.length, 5);
      expect(parts[0].length, 8);
      expect(parts[1].length, 4);
      expect(parts[2].length, 4);
      expect(parts[3].length, 4);
      expect(parts[4].length, 12);
      // All hex digits
      for (final part in parts) {
        expect(int.tryParse(part, radix: 16), isNotNull);
      }
    });

    test('generates unique UUIDs', () {
      final uuids = <String>{};
      for (var i = 0; i < 100; i++) {
        uuids.add(randomUUID());
      }
      expect(uuids.length, 100);
    });
  });

  group('crypto', () {
    test('subtle API is available in secure contexts', () {
      if (subtle.window.isSecureContext) {
        expect(() => subtle.window.crypto.subtle, returnsNormally);
        return;
      }

      expect(
        () => subtle.window.crypto.subtle,
        throwsA(
          isA<UnsupportedError>().having(
            (e) => e.message,
            'message',
            contains('secure context'),
          ),
        ),
      );
    });

    test('subtle API throws secure-context guidance when unavailable', () {
      expect(
        () => subtle.requireSubtleCrypto(null, false),
        throwsA(
          isA<UnsupportedError>().having(
            (e) => e.message,
            'message',
            allOf(contains('secure context'), contains('localhost')),
          ),
        ),
      );
    });

    test('subtle API throws missing-API guidance in secure contexts', () {
      expect(
        () => subtle.requireSubtleCrypto(null, true),
        throwsA(
          isA<UnsupportedError>().having(
            (e) => e.message,
            'message',
            allOf(contains('window.crypto.subtle'), contains('Web Crypto API')),
          ),
        ),
      );
    });

    test('getRandomValues: success', () {
      final data = Uint8List(16 * 1024);
      expect(data.every((e) => e == 0), isTrue);
      final values = data.toJS;
      subtle.window.crypto.getRandomValues(values);
      if (kIsWasm) {
        // In dart2wasm, the value is not reflected in Uint8List.
        expect(data.every((e) => e == 0), isTrue);
      } else {
        // In dart2js, the value is reflected in Uint8List.
        expect(data.every((e) => e == 0), isFalse);
      }
      expect(values.toDart.any((e) => e != 0), isTrue);
    });

    test('getRandomValues: too long', () {
      try {
        subtle.window.crypto.getRandomValues(Uint8List(1000000).toJS);
      } on subtle.JSDomException catch (e) {
        // dart2js throws QuotaExceededError
        expect(e.name, 'QuotaExceededError');
      } on Error catch (e) {
        expect(
          e.toString(),
          anyOf('JavaScriptError', startsWith('QuotaExceededError:')),
        );
      }
    });

    test('getRandomValues: not supported type', () {
      try {
        subtle.window.crypto.getRandomValues(Float32List(32).toJS);
      } on subtle.JSDomException catch (e) {
        // dart2js throws TypeMismatchError
        expect(e.name, 'TypeMismatchError');
      } on Error catch (e) {
        expect(
          e.toString(),
          anyOf('JavaScriptError', startsWith('TypeMismatchError:')),
        );
      }
    });
  });

  group('crypto.subtle', () {
    test('generateCryptoKey: success', () async {
      expect(
        await subtle.window.crypto.subtle
            .generateCryptoKey(
              const subtle.Algorithm(name: 'AES-GCM', length: 256).toJS,
              false,
              ['encrypt', 'decrypt'].toJS,
            )
            .toDart,
        isA<subtle.JSCryptoKey>()
            .having((key) => key.type, 'type', 'secret')
            .having((key) => key.extractable, 'extractable', false)
            .having(
              (key) => key.usages.toDartList,
              'usages',
              containsAll(['encrypt', 'decrypt']),
            ),
      );
    });

    test('generateCryptoKey: invalid keyUsages', () {
      expect(
        () async => await subtle.window.crypto.subtle
            .generateCryptoKey(
              const subtle.Algorithm(name: 'AES-GCM', length: 256).toJS,
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
            .having((key) => key.publicKey.type, 'publicKey.type', 'public')
            .having(
              (key) => key.publicKey.extractable,
              'publicKey.extractable',
              true,
            )
            .having(
              (key) => key.publicKey.usages.toDartList,
              'publicKey.usages',
              ['encrypt'],
            )
            .having((key) => key.privateKey.type, 'privateKey.type', 'private')
            .having(
              (key) => key.privateKey.extractable,
              'privateKey.extractable',
              false,
            )
            .having(
              (key) => key.privateKey.usages.toDartList,
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
            .having((key) => key.publicKey.type, 'publicKey.type', 'public')
            .having(
              (key) => key.publicKey.extractable,
              'publicKey.extractable',
              true,
            )
            .having(
              (key) => key.publicKey.usages.toDartList,
              'publicKey.usages',
              ['encrypt'],
            )
            .having((key) => key.privateKey.type, 'privateKey.type', 'private')
            .having(
              (key) => key.privateKey.extractable,
              'privateKey.extractable',
              false,
            )
            .having(
              (key) => key.privateKey.usages.toDartList,
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

extension on JSArray<JSString> {
  List<String> get toDartList => toDart.map((e) => e.toDart).toList();
}
