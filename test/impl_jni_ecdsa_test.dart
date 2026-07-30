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
import 'dart:isolate';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webcrypto/src/impl_ffi/impl_ffi.dart' as ffi_impl;
import 'package:webcrypto/src/impl_interface/impl_interface.dart';
import 'package:webcrypto/src/impl_jni/impl_jni.dart' as jni_impl;

import 'src/jni_test_setup.dart'
    if (dart.library.io) 'src/jni_test_setup_io.dart';

void main() {
  final skipReason = jniHelperSetupSkipReason;

  setUpAll(() {
    if (skipReason == null) {
      spawnJniForDesktopTests();
    }
  });

  for (final testCase
      in <
        ({
          EllipticCurve curve,
          HashImpl jniHash,
          HashImpl ffiHash,
          int signatureLength,
        })
      >[
        (
          curve: EllipticCurve.p256,
          jniHash: jni_impl.webCryptImpl.sha256,
          ffiHash: ffi_impl.webCryptImpl.sha256,
          signatureLength: 64,
        ),
        (
          curve: EllipticCurve.p384,
          jniHash: jni_impl.webCryptImpl.sha384,
          ffiHash: ffi_impl.webCryptImpl.sha384,
          signatureLength: 96,
        ),
        (
          curve: EllipticCurve.p521,
          jniHash: jni_impl.webCryptImpl.sha512,
          ffiHash: ffi_impl.webCryptImpl.sha512,
          signatureLength: 132,
        ),
      ]) {
    test('JCA ECDSA ${testCase.curve.name} interoperates with FFI', () async {
      final keyPair = await jni_impl.webCryptImpl.ecdsaPrivateKey.generateKey(
        testCase.curve,
      );
      final privateKey = keyPair.$1;
      final publicKey = keyPair.$2;
      final chunks = <Uint8List>[
        Uint8List.fromList(List<int>.generate(9000, (i) => i & 0xff)),
        Uint8List.fromList(utf8.encode('ECDSA interoperability')),
      ];

      final pkcs8 = await privateKey.exportPkcs8Key();
      final spki = await publicKey.exportSpkiKey();
      final ffiPrivateKey = await ffi_impl.webCryptImpl.ecdsaPrivateKey
          .importPkcs8Key(pkcs8, testCase.curve);
      final ffiPublicKey = await ffi_impl.webCryptImpl.ecdsaPublicKey
          .importSpkiKey(spki, testCase.curve);

      final jcaSignature = await privateKey.signStream(
        Stream.fromIterable(chunks),
        testCase.jniHash,
      );
      final ffiSignature = await ffiPrivateKey.signStream(
        Stream.fromIterable(chunks),
        testCase.ffiHash,
      );

      expect(jcaSignature, hasLength(testCase.signatureLength));
      expect(ffiSignature, hasLength(testCase.signatureLength));
      expect(
        await ffiPublicKey.verifyStream(
          jcaSignature,
          Stream.fromIterable(chunks),
          testCase.ffiHash,
        ),
        isTrue,
      );
      expect(
        await publicKey.verifyStream(
          ffiSignature,
          Stream.fromIterable(chunks),
          testCase.jniHash,
        ),
        isTrue,
      );

      final raw = await publicKey.exportRawKey();
      final importedRaw = await jni_impl.webCryptImpl.ecdsaPublicKey
          .importRawKey(raw, testCase.curve);
      expect(
        await importedRaw.verifyStream(
          jcaSignature,
          Stream.fromIterable(chunks),
          testCase.jniHash,
        ),
        isTrue,
      );
    }, skip: skipReason);
  }

  test('JCA ECDSA supports every backend hash', () async {
    final keyPair = await jni_impl.webCryptImpl.ecdsaPrivateKey.generateKey(
      EllipticCurve.p256,
    );
    final data = utf8.encode('ECDSA hash variants');

    for (final hash in <HashImpl>[
      jni_impl.webCryptImpl.sha1,
      jni_impl.webCryptImpl.sha256,
      jni_impl.webCryptImpl.sha384,
      jni_impl.webCryptImpl.sha512,
    ]) {
      final signature = await keyPair.$1.signBytes(data, hash);
      expect(signature, hasLength(64));
      expect(await keyPair.$2.verifyBytes(signature, data, hash), isTrue);
    }
  }, skip: skipReason);

  test('JCA ECDSA rejects malformed signatures', () async {
    final keyPair = await jni_impl.webCryptImpl.ecdsaPrivateKey.generateKey(
      EllipticCurve.p256,
    );
    final data = utf8.encode('ECDSA signature validation');
    final signature = await keyPair.$1.signBytes(
      data,
      jni_impl.webCryptImpl.sha256,
    );

    expect(
      await keyPair.$2.verifyBytes(
        Uint8List.sublistView(signature, 1),
        data,
        jni_impl.webCryptImpl.sha256,
      ),
      isFalse,
    );
    expect(
      await keyPair.$2.verifyBytes(
        Uint8List(64),
        data,
        jni_impl.webCryptImpl.sha256,
      ),
      isFalse,
    );
  }, skip: skipReason);

  test('JCA ECDSA validates key formats and JWK metadata', () async {
    final keyPair = await jni_impl.webCryptImpl.ecdsaPrivateKey.generateKey(
      EllipticCurve.p256,
    );
    final privateJwk = await keyPair.$1.exportJsonWebKey();
    final publicJwk = await keyPair.$2.exportJsonWebKey();

    expect(privateJwk['kty'], 'EC');
    expect(privateJwk['use'], 'sig');
    expect(privateJwk['crv'], 'P-256');
    expect(privateJwk.keys, containsAll(<String>['x', 'y', 'd']));
    expect(publicJwk.keys, isNot(contains('d')));

    final wrongCurve = Map<String, dynamic>.of(publicJwk)..['crv'] = 'P-384';
    await expectLater(
      jni_impl.webCryptImpl.ecdsaPublicKey.importJsonWebKey(
        wrongCurve,
        EllipticCurve.p256,
      ),
      throwsA(isA<FormatException>()),
    );

    final wrongUse = Map<String, dynamic>.of(publicJwk)..['use'] = 'enc';
    await expectLater(
      jni_impl.webCryptImpl.ecdsaPublicKey.importJsonWebKey(
        wrongUse,
        EllipticCurve.p256,
      ),
      throwsA(isA<FormatException>()),
    );

    final wrongAlg = Map<String, dynamic>.of(privateJwk)..['alg'] = 'ES384';
    await expectLater(
      jni_impl.webCryptImpl.ecdsaPrivateKey.importJsonWebKey(
        wrongAlg,
        EllipticCurve.p256,
      ),
      throwsA(isA<FormatException>()),
    );

    final otherKeyPair = await jni_impl.webCryptImpl.ecdsaPrivateKey
        .generateKey(EllipticCurve.p256);
    final otherPublicJwk = await otherKeyPair.$2.exportJsonWebKey();
    final mismatchedPoint = Map<String, dynamic>.of(privateJwk)
      ..['x'] = otherPublicJwk['x']
      ..['y'] = otherPublicJwk['y'];
    await expectLater(
      jni_impl.webCryptImpl.ecdsaPrivateKey.importJsonWebKey(
        mismatchedPoint,
        EllipticCurve.p256,
      ),
      throwsA(isA<FormatException>()),
    );

    final pkcs8 = await keyPair.$1.exportPkcs8Key();
    final spki = await keyPair.$2.exportSpkiKey();
    await expectLater(
      jni_impl.webCryptImpl.ecdsaPrivateKey.importPkcs8Key(
        Uint8List.fromList(<int>[...pkcs8, 0]),
        EllipticCurve.p256,
      ),
      throwsA(isA<FormatException>()),
    );
    await expectLater(
      jni_impl.webCryptImpl.ecdsaPublicKey.importSpkiKey(
        Uint8List.fromList(<int>[...spki, 0]),
        EllipticCurve.p256,
      ),
      throwsA(isA<FormatException>()),
    );
  }, skip: skipReason);

  test('JCA ECDSA key wrappers cannot cross isolate boundaries', () async {
    final keyPair = await jni_impl.webCryptImpl.ecdsaPrivateKey.generateKey(
      EllipticCurve.p256,
    );
    for (final key in <Object>[keyPair.$1, keyPair.$2]) {
      final ready = ReceivePort();
      final isolate = await Isolate.spawn(_waitForMessage, ready.sendPort);
      try {
        final destination = await ready.first as SendPort;
        expect(() => destination.send(key), throwsA(isA<ArgumentError>()));
      } finally {
        isolate.kill(priority: Isolate.immediate);
        ready.close();
      }
    }
  }, skip: skipReason);
}

Future<void> _waitForMessage(SendPort ready) async {
  final messages = ReceivePort();
  ready.send(messages.sendPort);
  await messages.first;
}
