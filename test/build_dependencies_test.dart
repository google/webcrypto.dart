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

import 'dart:io';

import 'package:test/test.dart';

import '../hook/build_dependencies.dart';

void main() {
  test('build dependencies include native configuration and include files', () {
    final packageRoot = Directory.systemTemp.createTempSync(
      'webcrypto_build_dependencies_',
    );
    addTearDown(() => packageRoot.deleteSync(recursive: true));

    final paths = [
      'src/webcrypto.c',
      'src/toolchain.cmake',
      'src/CMakeLists.txt',
      'third_party/boringssl/src/crypto/fipsmodule/aes/aes.cc.inc',
    ];
    for (final path in paths) {
      File('${packageRoot.path}/$path')
        ..createSync(recursive: true)
        ..writeAsStringSync('// test input');
    }
    File('${packageRoot.path}/src/README.txt')
      ..createSync(recursive: true)
      ..writeAsStringSync('not a build dependency');

    final dependencies = buildDependencies(
      packageRoot.uri,
    ).map((uri) => uri.toFilePath()).toSet();

    for (final path in paths) {
      expect(dependencies, contains('${packageRoot.path}/$path'));
    }
    expect(dependencies, isNot(contains('${packageRoot.path}/src/README.txt')));
  });
}
