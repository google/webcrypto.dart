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
  late RsaPssPrivateKeyImpl privateKey;
  late RsaPssPublicKeyImpl publicKey;

  setUpAll(() async {
    if (skipReason != null) {
      return;
    }

    spawnJniForDesktopTests();
    final keyPair = await jni_impl.webCryptImpl.rsaPssPrivateKey.generateKey(
      2048,
      BigInt.from(65537),
      jni_impl.webCryptImpl.sha256,
    );
    privateKey = keyPair.$1;
    publicKey = keyPair.$2;
  });

  test('JCA RSA-PSS parameters and streams interoperate with FFI', () async {
    const saltLength = 20;
    final chunks = <Uint8List>[
      Uint8List.fromList(List<int>.generate(9000, (i) => i & 0xff)),
      Uint8List.fromList(utf8.encode('RSA-PSS interoperability')),
    ];
    final ffiPrivateKey = await ffi_impl.webCryptImpl.rsaPssPrivateKey
        .importPkcs8Key(
          await privateKey.exportPkcs8Key(),
          ffi_impl.webCryptImpl.sha256,
        );
    final ffiPublicKey = await ffi_impl.webCryptImpl.rsaPssPublicKey
        .importSpkiKey(
          await publicKey.exportSpkiKey(),
          ffi_impl.webCryptImpl.sha256,
        );

    final jcaSignature = await privateKey.signStream(
      Stream.fromIterable(chunks),
      saltLength,
    );
    final ffiSignature = await ffiPrivateKey.signStream(
      Stream.fromIterable(chunks),
      saltLength,
    );

    expect(
      await ffiPublicKey.verifyStream(
        jcaSignature,
        Stream.fromIterable(chunks),
        saltLength,
      ),
      isTrue,
    );
    expect(
      await publicKey.verifyStream(
        ffiSignature,
        Stream.fromIterable(chunks),
        saltLength,
      ),
      isTrue,
    );
  }, skip: skipReason);

  test('JCA RSA-PSS treats malformed signatures as invalid', () async {
    final data = utf8.encode('message');
    final signature = await privateKey.signBytes(data, 32);
    final modified = Uint8List.fromList(signature)..[0] ^= 0x01;

    expect(await publicKey.verifyBytes(modified, data, 32), isFalse);
    expect(
      await publicKey.verifyBytes(
        Uint8List.sublistView(signature, 1),
        data,
        32,
      ),
      isFalse,
    );
  }, skip: skipReason);

  test('JCA RSA-PSS validates and translates invalid salt lengths', () async {
    final data = utf8.encode('message');

    expect(() => privateKey.signBytes(data, -1), throwsArgumentError);
    expect(
      () => publicKey.verifyBytes(Uint8List(256), data, -1),
      throwsArgumentError,
    );
    await expectLater(
      privateKey.signBytes(data, 512),
      throwsA(isA<OperationError>()),
    );
  }, skip: skipReason);
}
