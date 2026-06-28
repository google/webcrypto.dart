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

  test('JCA digest matches known SHA-256 vector', () async {
    final data = utf8.encode('hello-world');
    final digest = await jni_impl.webCryptImpl.sha256.digestBytes(data);
    final ffiDigest = await ffi_impl.webCryptImpl.sha256.digestBytes(data);

    expect(digest, ffiDigest);
    expect(
      base64Encode(digest),
      'r6J7RNQ7Aqn+pB0TztwuQBbPz4fF2/mQ5ZNmmqjOKG0=',
    );
  }, skip: skipReason);

  test('JCA digest stream matches known SHA-512 vector', () async {
    final data = utf8.encode('hello-world');
    final digest = await jni_impl.webCryptImpl.sha512.digestStream(
      Stream.value(data),
    );
    final ffiDigest = await ffi_impl.webCryptImpl.sha512.digestStream(
      Stream.value(data),
    );

    expect(digest, ffiDigest);
    expect(
      base64Encode(digest),
      'au78KRIqOWLJDvg09sqtADO//NYpQbemIFppXMOeJ2fbd3inrXbRc6CDueFLIQ3AISkj'
      '9IGyhceEqx/jQNf/TQ==',
    );
  }, skip: skipReason);
}
