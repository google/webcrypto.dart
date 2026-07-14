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
  late RsaSsaPkcs1V15PrivateKeyImpl privateKey;
  late RsaSsaPkcs1V15PublicKeyImpl publicKey;

  setUpAll(() async {
    if (skipReason != null) {
      return;
    }

    spawnJniForDesktopTests();
    final keyPair = await jni_impl.webCryptImpl.rsaSsaPkcs1v15PrivateKey
        .generateKey(2048, BigInt.from(65537), jni_impl.webCryptImpl.sha256);
    privateKey = keyPair.$1;
    publicKey = keyPair.$2;
  });

  test(
    'JCA RSASSA-PKCS1-v1_5 keys and signatures interoperate with FFI',
    () async {
      final chunks = <Uint8List>[
        utf8.encode('RSASSA-PKCS1-v1_5 '),
        utf8.encode('interoperability'),
      ];
      final pkcs8 = await privateKey.exportPkcs8Key();
      final spki = await publicKey.exportSpkiKey();
      final ffiPrivateKey = await ffi_impl.webCryptImpl.rsaSsaPkcs1v15PrivateKey
          .importPkcs8Key(pkcs8, ffi_impl.webCryptImpl.sha256);
      final ffiPublicKey = await ffi_impl.webCryptImpl.rsaSsaPkcs1v15PublicKey
          .importSpkiKey(spki, ffi_impl.webCryptImpl.sha256);

      final jcaSignature = await privateKey.signStream(
        Stream.fromIterable(chunks),
      );
      final ffiSignature = await ffiPrivateKey.signStream(
        Stream.fromIterable(chunks),
      );

      expect(jcaSignature, ffiSignature);
      expect(
        await ffiPublicKey.verifyStream(
          jcaSignature,
          Stream.fromIterable(chunks),
        ),
        isTrue,
      );
      expect(
        await publicKey.verifyStream(ffiSignature, Stream.fromIterable(chunks)),
        isTrue,
      );
    },
    skip: skipReason,
  );

  test('JCA RSASSA-PKCS1-v1_5 rejects malformed signatures', () async {
    final data = utf8.encode('message');
    final signature = await privateKey.signBytes(data);
    final modified = Uint8List.fromList(signature)..[0] ^= 0x01;

    expect(await publicKey.verifyBytes(modified, data), isFalse);
    expect(
      await publicKey.verifyBytes(Uint8List.sublistView(signature, 1), data),
      isFalse,
    );
  }, skip: skipReason);

  test('JCA RSASSA-PKCS1-v1_5 exports and validates RSA JWK values', () async {
    final privateJwk = await privateKey.exportJsonWebKey();
    final publicJwk = await publicKey.exportJsonWebKey();

    expect(privateJwk['kty'], 'RSA');
    expect(privateJwk['use'], 'sig');
    expect(privateJwk['alg'], 'RS256');
    expect(
      privateJwk.keys,
      containsAll(<String>['d', 'p', 'q', 'dp', 'dq', 'qi']),
    );
    expect(publicJwk['kty'], 'RSA');
    expect(publicJwk['use'], 'sig');
    expect(publicJwk['alg'], 'RS256');
    expect(publicJwk.keys, isNot(contains('d')));

    final importedPrivate = await jni_impl.webCryptImpl.rsaSsaPkcs1v15PrivateKey
        .importJsonWebKey(privateJwk, jni_impl.webCryptImpl.sha256);
    final importedPublic = await jni_impl.webCryptImpl.rsaSsaPkcs1v15PublicKey
        .importJsonWebKey(publicJwk, jni_impl.webCryptImpl.sha256);
    final data = utf8.encode('JWK round trip');
    final signature = await importedPrivate.signBytes(data);
    expect(await importedPublic.verifyBytes(signature, data), isTrue);

    final invalidPublicJwk = Map<String, dynamic>.of(publicJwk);
    invalidPublicJwk['n'] = _prependZeroToBase64Url(
      invalidPublicJwk['n'] as String,
    );
    await expectLater(
      jni_impl.webCryptImpl.rsaSsaPkcs1v15PublicKey.importJsonWebKey(
        invalidPublicJwk,
        jni_impl.webCryptImpl.sha256,
      ),
      throwsA(
        isA<FormatException>().having(
          (e) => e.message,
          'message',
          contains('must not have leading zeros'),
        ),
      ),
    );
  }, skip: skipReason);
}

String _prependZeroToBase64Url(String encoded) {
  final padded = encoded.padRight(
    encoded.length + ((4 - encoded.length % 4) % 4),
    '=',
  );
  final bytes = base64Url.decode(padded);
  return base64Url.encode(<int>[0, ...bytes]).replaceAll('=', '');
}
