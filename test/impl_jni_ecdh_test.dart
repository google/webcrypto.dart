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

  for (final testCase in <({EllipticCurve curve, int maxLength})>[
    (curve: EllipticCurve.p256, maxLength: 256),
    (curve: EllipticCurve.p384, maxLength: 384),
    (curve: EllipticCurve.p521, maxLength: 528),
  ]) {
    test('JCA ECDH ${testCase.curve.name} interoperates with FFI', () async {
      final alice = await jni_impl.webCryptImpl.ecdhPrivateKey.generateKey(
        testCase.curve,
      );
      final bob = await jni_impl.webCryptImpl.ecdhPrivateKey.generateKey(
        testCase.curve,
      );

      final ffiAlice = await ffi_impl.webCryptImpl.ecdhPrivateKey
          .importPkcs8Key(await alice.$1.exportPkcs8Key(), testCase.curve);
      final ffiBob = await ffi_impl.webCryptImpl.ecdhPublicKey.importSpkiKey(
        await bob.$2.exportSpkiKey(),
        testCase.curve,
      );

      for (final length in <int>[testCase.maxLength, testCase.maxLength - 1]) {
        final jcaDerived = await alice.$1.deriveBits(length, bob.$2);
        final reciprocal = await bob.$1.deriveBits(length, alice.$2);
        final ffiDerived = await ffiAlice.deriveBits(length, ffiBob);

        expect(jcaDerived, hasLength((length + 7) ~/ 8));
        expect(jcaDerived, reciprocal);
        expect(jcaDerived, ffiDerived);
        if (length % 8 != 0) {
          expect(jcaDerived.last & ((1 << (8 - (length % 8))) - 1), 0);
        }
      }

      final rawPublicKey = await bob.$2.exportRawKey();
      final importedPublicKey = await jni_impl.webCryptImpl.ecdhPublicKey
          .importRawKey(rawPublicKey, testCase.curve);
      expect(
        await alice.$1.deriveBits(testCase.maxLength, importedPublicKey),
        await alice.$1.deriveBits(testCase.maxLength, bob.$2),
      );
    }, skip: skipReason);
  }

  test('JCA ECDH validates JWK metadata and derives bounds', () async {
    final alice = await jni_impl.webCryptImpl.ecdhPrivateKey.generateKey(
      EllipticCurve.p256,
    );
    final bob = await jni_impl.webCryptImpl.ecdhPrivateKey.generateKey(
      EllipticCurve.p256,
    );
    final privateJwk = await alice.$1.exportJsonWebKey();
    final publicJwk = await bob.$2.exportJsonWebKey();

    expect(privateJwk['kty'], 'EC');
    expect(privateJwk['crv'], 'P-256');
    expect(privateJwk, isNot(contains('use')));
    expect(publicJwk, isNot(contains('d')));
    expect(publicJwk, isNot(contains('use')));

    final withUse = Map<String, dynamic>.of(publicJwk)..['use'] = 'enc';
    final withArbitraryAlg = Map<String, dynamic>.of(withUse)
      ..['alg'] = 'custom-ecdh-algorithm';
    final importedPublicKey = await jni_impl.webCryptImpl.ecdhPublicKey
        .importJsonWebKey(withArbitraryAlg, EllipticCurve.p256);
    expect(
      await alice.$1.deriveBits(256, importedPublicKey),
      await alice.$1.deriveBits(256, bob.$2),
    );

    final wrongUse = Map<String, dynamic>.of(publicJwk)..['use'] = 'sig';
    await expectLater(
      jni_impl.webCryptImpl.ecdhPublicKey.importJsonWebKey(
        wrongUse,
        EllipticCurve.p256,
      ),
      throwsA(isA<FormatException>()),
    );
    await expectLater(
      alice.$1.deriveBits(257, bob.$2),
      throwsA(isA<OperationError>()),
    );
    await expectLater(alice.$1.deriveBits(-1, bob.$2), throwsArgumentError);
    expect(await alice.$1.deriveBits(0, bob.$2), isEmpty);

    final p384 = await jni_impl.webCryptImpl.ecdhPrivateKey.generateKey(
      EllipticCurve.p384,
    );
    await expectLater(alice.$1.deriveBits(256, p384.$2), throwsArgumentError);
  }, skip: skipReason);

  test('JCA ECDH key wrappers cannot cross isolate boundaries', () async {
    final keyPair = await jni_impl.webCryptImpl.ecdhPrivateKey.generateKey(
      EllipticCurve.p256,
    );
    for (final key in <Object>[keyPair.$1, keyPair.$2]) {
      final ready = ReceivePort();
      final isolate = await Isolate.spawn(_waitForMessage, ready.sendPort);
      try {
        final destination = await ready.first as SendPort;
        expect(() => destination.send(key), throwsArgumentError);
      } finally {
        isolate.kill(priority: Isolate.immediate);
        ready.close();
      }
    }
  }, skip: skipReason);
}

void _waitForMessage(SendPort ready) {
  final messages = ReceivePort();
  ready.send(messages.sendPort);
}
