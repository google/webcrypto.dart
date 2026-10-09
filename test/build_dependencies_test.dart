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

import 'dart:io';

import 'package:test/test.dart';

import '../hook/build.dart';

void main() {
  test('tracks CMake configuration and nested BoringSSL includes', () {
    final package = Directory.systemTemp.createTempSync(
      'webcrypto-build-test-',
    );
    addTearDown(() => package.deleteSync(recursive: true));

    const included = [
      'src/CMakeLists.txt',
      'src/webcrypto.c',
      'third_party/boringssl/src/crypto/fipsmodule/aes/aes.cc.inc',
      'third_party/boringssl/cmake/config.cmake',
    ];
    const excluded = [
      'src/README.md',
      'third_party/boringssl/src/crypto/fipsmodule/aes/aes.cc.inc.bak',
    ];

    for (final path in [...included, ...excluded]) {
      final file = File.fromUri(package.uri.resolve(path));
      file.parent.createSync(recursive: true);
      file.writeAsStringSync('');
    }

    expect(
      buildDependencies(package.uri).toSet(),
      included.map(package.uri.resolve).toSet(),
    );
  });
}
