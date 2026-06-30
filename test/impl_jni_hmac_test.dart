// Copyright 2020 Google LLC
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
import 'package:webcrypto/src/impl_jni/impl_jni.dart' as jni_impl;

import 'src/jni_test_setup.dart'
    if (dart.library.io) 'src/jni_test_setup_io.dart';

void main() {
  final skipReason = jniHelperSetupSkipReason;

  setUpAll(() {
    if (skipReason != null) {
      return;
    }

    spawnJniForDesktopTests();
  });

  test('JCA HMAC-SHA-256 matches RFC 4231 test vector', () async {
    final keyData = List<int>.filled(20, 0x0b);
    final data = utf8.encode('Hi There');

    final key = await jni_impl.webCryptImpl.hmacSecretKey.importRawKey(
      keyData,
      jni_impl.webCryptImpl.sha256,
    );
    final signature = await key.signBytes(data);

    final ffiKey = await ffi_impl.webCryptImpl.hmacSecretKey.importRawKey(
      keyData,
      ffi_impl.webCryptImpl.sha256,
    );
    final ffiSignature = await ffiKey.signBytes(data);

    expect(signature, ffiSignature);
    expect(
      base64Encode(signature),
      'sDRMYdjbOFNcqK/OrwvxK4gdwgDJgz2nJuk3bC4yz/c=',
    );
    expect(await key.verifyBytes(signature, data), isTrue);

    final badSignature = Uint8List.fromList(signature);
    badSignature[badSignature.length - 1] ^= 0x01;
    expect(await key.verifyBytes(badSignature, data), isFalse);
  }, skip: skipReason);

  test('JCA HMAC-SHA-512 stream signing matches FFI', () async {
    final keyData = List<int>.filled(20, 0x0b);
    final chunks = [utf8.encode('Hi '), utf8.encode('There')];

    final key = await jni_impl.webCryptImpl.hmacSecretKey.importRawKey(
      keyData,
      jni_impl.webCryptImpl.sha512,
    );
    final signature = await key.signStream(Stream.fromIterable(chunks));

    final ffiKey = await ffi_impl.webCryptImpl.hmacSecretKey.importRawKey(
      keyData,
      ffi_impl.webCryptImpl.sha512,
    );
    final ffiSignature = await ffiKey.signStream(Stream.fromIterable(chunks));

    expect(signature, ffiSignature);
    expect(
      base64Encode(signature),
      'h6p83qXvYZ1P8LQkGh1ssCN59OLOTsJ4etCzBUXhfN7aqDO31rinAgOLJ06uo/Tk'
      'vp2RTuth8XAuaWwgOhJoVA==',
    );
    expect(
      await key.verifyStream(signature, Stream.fromIterable(chunks)),
      isTrue,
    );
  }, skip: skipReason);

  test('JCA HMAC exports and imports JSON Web Keys', () async {
    final keyData = utf8.encode('sample-hmac-key');
    final key = await jni_impl.webCryptImpl.hmacSecretKey.importRawKey(
      keyData,
      jni_impl.webCryptImpl.sha384,
    );

    final jwk = await key.exportJsonWebKey();
    expect(jwk['kty'], 'oct');
    expect(jwk['use'], 'sig');
    expect(jwk['alg'], 'HS384');
    expect(jwk['k'], 'c2FtcGxlLWhtYWMta2V5');

    final imported = await jni_impl.webCryptImpl.hmacSecretKey.importJsonWebKey(
      jwk,
      jni_impl.webCryptImpl.sha384,
    );
    final data = utf8.encode('message');

    expect(await imported.signBytes(data), await key.signBytes(data));
  }, skip: skipReason);

  test('JCA HMAC generateKey supports non-byte-aligned key lengths', () async {
    final key = await jni_impl.webCryptImpl.hmacSecretKey.generateKey(
      jni_impl.webCryptImpl.sha512,
      length: 37,
    );

    final keyData = await key.exportRawKey();
    expect(keyData, hasLength(5));
    expect(keyData.last & 0x07, 0);

    final signature = await key.signBytes(utf8.encode('message'));
    expect(await key.verifyBytes(signature, utf8.encode('message')), isTrue);
  }, skip: skipReason);
}
