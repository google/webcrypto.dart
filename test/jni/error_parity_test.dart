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

import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webcrypto/src/impl_ffi/impl_ffi.dart' as ffi_impl;
import 'package:webcrypto/src/impl_interface/impl_interface.dart';
import 'package:webcrypto/src/impl_jni/impl_jni.dart' as jni_impl;

import '../src/jni_test_setup.dart'
    if (dart.library.io) '../src/jni_test_setup_io.dart';

void main() {
  final skipReason = jniHelperSetupSkipReason;

  setUpAll(() {
    if (skipReason == null) {
      spawnJniForDesktopTests();
    }
  });

  group('FFI and JNI public error categories', () {
    test('reject malformed and unsupported AES keys consistently', () async {
      await _expectSameErrorCategory(
        () => ffi_impl.webCryptImpl.aesCbcSecretKey.importRawKey(Uint8List(15)),
        () => jni_impl.webCryptImpl.aesCbcSecretKey.importRawKey(Uint8List(15)),
        _ErrorCategory.format,
      );
      await _expectSameErrorCategory(
        () => ffi_impl.webCryptImpl.aesCbcSecretKey.importRawKey(Uint8List(24)),
        () => jni_impl.webCryptImpl.aesCbcSecretKey.importRawKey(Uint8List(24)),
        _ErrorCategory.unsupported,
      );
    });

    test('reject invalid AES-CBC parameters consistently', () async {
      final ffiKey = await ffi_impl.webCryptImpl.aesCbcSecretKey.importRawKey(
        Uint8List(16),
      );
      final jniKey = await jni_impl.webCryptImpl.aesCbcSecretKey.importRawKey(
        Uint8List(16),
      );

      await _expectSameErrorCategory(
        () => ffiKey.encryptBytes(Uint8List(16), Uint8List(15)),
        () => jniKey.encryptBytes(Uint8List(16), Uint8List(15)),
        _ErrorCategory.argument,
      );
    });

    test('translate AES-CBC padding failures consistently', () async {
      final keyData = base64Decode('nJ0IrxKwen1VN2/rfLsmmA==');
      final iv = base64Decode('AAEECRAZJDFAUWR5kKnE4Q==');
      final plaintext = Uint8List.fromList(utf8.encode('padding check'));
      final ffiKey = await ffi_impl.webCryptImpl.aesCbcSecretKey.importRawKey(
        keyData,
      );
      final jniKey = await jni_impl.webCryptImpl.aesCbcSecretKey.importRawKey(
        keyData,
      );
      final ciphertext = Uint8List.fromList(
        await ffiKey.encryptBytes(plaintext, iv),
      )..last ^= 0x01;

      await _expectSameErrorCategory(
        () => ffiKey.decryptBytes(ciphertext, iv),
        () => jniKey.decryptBytes(ciphertext, iv),
        _ErrorCategory.operation,
      );
    });

    test('translate AES-GCM authentication failures consistently', () async {
      final keyData = base64Decode(
        'uIfV8fgL3cR69VFEZBwFVKZYAEWRGl3k6JlT6mGAd1o=',
      );
      final iv = base64Decode('AAEECRAZJDFAUWR5kKnE4Q==');
      final additionalData = Uint8List.fromList(utf8.encode('expected aad'));
      final wrongAdditionalData = Uint8List.fromList(utf8.encode('wrong aad'));
      final ffiKey = await ffi_impl.webCryptImpl.aesGcmSecretKey.importRawKey(
        keyData,
      );
      final jniKey = await jni_impl.webCryptImpl.aesGcmSecretKey.importRawKey(
        keyData,
      );
      final ciphertext = await ffiKey.encryptBytes(
        Uint8List.fromList(utf8.encode('authenticated message')),
        iv,
        additionalData: additionalData,
      );

      await _expectSameErrorCategory(
        () => ffiKey.decryptBytes(
          ciphertext,
          iv,
          additionalData: wrongAdditionalData,
        ),
        () => jniKey.decryptBytes(
          ciphertext,
          iv,
          additionalData: wrongAdditionalData,
        ),
        _ErrorCategory.operation,
      );
    });

    test('reject malformed asymmetric key encodings consistently', () async {
      final malformedDer = Uint8List.fromList(<int>[0x30, 0x00]);

      await _expectSameErrorCategory(
        () => ffi_impl.webCryptImpl.rsaOaepPrivateKey.importPkcs8Key(
          malformedDer,
          ffi_impl.webCryptImpl.sha256,
        ),
        () => jni_impl.webCryptImpl.rsaOaepPrivateKey.importPkcs8Key(
          malformedDer,
          jni_impl.webCryptImpl.sha256,
        ),
        _ErrorCategory.format,
      );
      await _expectSameErrorCategory(
        () => ffi_impl.webCryptImpl.ecdsaPrivateKey.importPkcs8Key(
          malformedDer,
          EllipticCurve.p256,
        ),
        () => jni_impl.webCryptImpl.ecdsaPrivateKey.importPkcs8Key(
          malformedDer,
          EllipticCurve.p256,
        ),
        _ErrorCategory.format,
      );
    });
  }, skip: skipReason);
}

enum _ErrorCategory { argument, format, operation, unsupported }

Future<void> _expectSameErrorCategory(
  Future<Object?> Function() ffiOperation,
  Future<Object?> Function() jniOperation,
  _ErrorCategory expected,
) async {
  final ffiError = await _captureError(ffiOperation);
  final jniError = await _captureError(jniOperation);

  expect(_errorCategory(ffiError), expected, reason: 'FFI: $ffiError');
  expect(_errorCategory(jniError), expected, reason: 'JNI: $jniError');
}

Future<Object> _captureError(Future<Object?> Function() operation) async {
  try {
    await operation();
  } catch (error) {
    return error;
  }
  fail('Expected the operation to throw.');
}

_ErrorCategory? _errorCategory(Object error) => switch (error) {
  FormatException() => _ErrorCategory.format,
  OperationError() => _ErrorCategory.operation,
  UnsupportedError() => _ErrorCategory.unsupported,
  ArgumentError() => _ErrorCategory.argument,
  _ => null,
};
