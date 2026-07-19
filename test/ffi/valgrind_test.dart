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

/// Runs [valgrind_target.dart] under Valgrind when the test suite runs on
/// Linux. Other platforms, and Linux environments without Valgrind, skip it.
@TestOn('vm')
@Timeout(Duration(minutes: 3))
library;

import 'dart:io';

import 'package:test/test.dart';

void main() {
  test('FFI operations are memory-safe under Valgrind', () async {
    if (!Platform.isLinux) {
      markTestSkipped('Valgrind testing is only supported on Linux.');
      return;
    }

    final valgrind = Process.runSync('which', ['valgrind']);
    if (valgrind.exitCode != 0) {
      markTestSkipped('Valgrind is not installed.');
      return;
    }

    final result = await Process.run('valgrind', [
      '--tool=memcheck',
      '--leak-check=full',
      '--show-leak-kinds=definite,possible',
      '--errors-for-leak-kinds=definite',
      '--track-origins=yes',
      '--error-exitcode=1',
      Platform.resolvedExecutable,
      'run',
      'test/ffi/valgrind_target.dart',
    ]);

    expect(
      result.exitCode,
      0,
      reason:
          'Valgrind failed.\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}',
    );
  });
}
