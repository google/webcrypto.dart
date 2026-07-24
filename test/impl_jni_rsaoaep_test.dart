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

import 'src/jni_test_setup.dart'
    if (dart.library.io) 'src/jni_test_setup_io.dart';

void main() {
  final skipReason = jniHelperSetupSkipReason;
  late RsaOaepPrivateKeyImpl privateKey;
  late RsaOaepPublicKeyImpl publicKey;

  setUpAll(() async {
    if (skipReason != null) {
      return;
    }

    spawnJniForDesktopTests();
    final keyPair = await jni_impl.webCryptImpl.rsaOaepPrivateKey.generateKey(
      2048,
      BigInt.from(65537),
      jni_impl.webCryptImpl.sha256,
    );
    privateKey = keyPair.$1;
    publicKey = keyPair.$2;
  });

  test('JCA RSA-OAEP digest, MGF1, and label interoperate with FFI', () async {
    final plaintext = Uint8List.fromList(utf8.encode('RSA-OAEP message'));
    final label = Uint8List.fromList(utf8.encode('context label'));
    final ffiPrivateKey = await ffi_impl.webCryptImpl.rsaOaepPrivateKey
        .importPkcs8Key(
          await privateKey.exportPkcs8Key(),
          ffi_impl.webCryptImpl.sha256,
        );
    final ffiPublicKey = await ffi_impl.webCryptImpl.rsaOaepPublicKey
        .importSpkiKey(
          await publicKey.exportSpkiKey(),
          ffi_impl.webCryptImpl.sha256,
        );

    final jcaCiphertext = await publicKey.encryptBytes(plaintext, label: label);
    final ffiCiphertext = await ffiPublicKey.encryptBytes(
      plaintext,
      label: label,
    );

    expect(
      await ffiPrivateKey.decryptBytes(jcaCiphertext, label: label),
      plaintext,
    );
    expect(
      await privateKey.decryptBytes(ffiCiphertext, label: label),
      plaintext,
    );
  }, skip: skipReason);

  test('JCA RSA-OAEP treats null and empty labels equivalently', () async {
    final plaintext = Uint8List.fromList(utf8.encode('empty label'));
    final ciphertext = await publicKey.encryptBytes(plaintext);

    expect(
      await privateKey.decryptBytes(ciphertext, label: Uint8List(0)),
      plaintext,
    );
  }, skip: skipReason);

  test('JCA RSA-OAEP translates attacker-controlled failures', () async {
    final plaintext = Uint8List.fromList(utf8.encode('message'));
    final ciphertext = await publicKey.encryptBytes(
      plaintext,
      label: utf8.encode('expected'),
    );

    await expectLater(
      privateKey.decryptBytes(ciphertext, label: utf8.encode('wrong')),
      throwsA(isA<OperationError>()),
    );

    // A 2048-bit RSA key with SHA-256 accepts at most 190 plaintext bytes.
    await expectLater(
      publicKey.encryptBytes(Uint8List(191)),
      throwsA(isA<OperationError>()),
    );
  }, skip: skipReason);
}
