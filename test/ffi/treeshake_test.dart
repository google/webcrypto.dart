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
@Timeout(Duration(minutes: 10))
library;

import 'dart:io';

import 'package:test/test.dart';

void main() {
  test('dart build verifies link hook treeshaking and disable_treeshaking user define', () async {
    final tempDirTreeshaken =
        Directory.systemTemp.createTempSync('webcrypto_treeshaken_');
    final tempDirDisabled =
        Directory.systemTemp.createTempSync('webcrypto_disabled_');

    try {
      final baseEnv = Map<String, String>.from(Platform.environment);
      const llvmPath = '/usr/lib/llvm-19/bin';
      if (Directory(llvmPath).existsSync()) {
        final currentPath = baseEnv['PATH'] ?? '';
        baseEnv['PATH'] = '$llvmPath:$currentPath';
      }

      // 1. Build WITH treeshaking (default)
      final resultTreeshaken = await Process.run(
        Platform.resolvedExecutable,
        [
          'build',
          'cli',
          '-t',
          'test/ffi/treeshake_target.dart',
          '-o',
          tempDirTreeshaken.path,
        ],
        environment: baseEnv,
        workingDirectory: Directory.current.path,
      );

      expect(
        resultTreeshaken.exitCode,
        0,
        reason:
            'dart build cli (treeshaken) failed.\nstdout:\n${resultTreeshaken.stdout}\nstderr:\n${resultTreeshaken.stderr}',
      );

      // Verify link hook treeshaking output log
      expect(
        resultTreeshaken.stdout.toString(),
        contains('webcrypto treeshaking enabled'),
        reason: 'Link hook did not output treeshaking log.',
      );

      final dylibTreeshaken = _findDynamicLibrary([
        tempDirTreeshaken,
        Directory('.dart_tool/lib'),
      ]);
      expect(
        dylibTreeshaken,
        isNotNull,
        reason: 'No dynamic library found after treeshaken build.',
      );

      final sizeTreeshaken = dylibTreeshaken!.lengthSync();
      final sizeTreeshakenMB = sizeTreeshaken / (1024 * 1024);

      stdout.writeln(
        'Treeshaken library size: ${sizeTreeshakenMB.toStringAsFixed(2)} MB (${sizeTreeshaken} bytes)',
      );

      // Verify treeshaken size is below 5 MB limit
      expect(
        sizeTreeshakenMB,
        lessThan(5.0),
        reason: 'Treeshaken binary size exceeded 5.0 MB limit.',
      );

      // 2. Build WITHOUT treeshaking (disable_treeshaking = true)
      // Invalidate shared link cache to re-execute link hook
      final sharedLinkDir =
          Directory('.dart_tool/hooks_runner/shared/webcrypto/link');
      if (sharedLinkDir.existsSync()) {
        sharedLinkDir.deleteSync(recursive: true);
      }

      final envDisabled = Map<String, String>.from(baseEnv)
        ..['WEBCRYPTO_DISABLE_TREESHAKING'] = 'true';

      final resultDisabled = await Process.run(
        Platform.resolvedExecutable,
        [
          'build',
          'cli',
          '-t',
          'test/ffi/treeshake_target.dart',
          '-o',
          tempDirDisabled.path,
        ],
        environment: envDisabled,
        workingDirectory: Directory.current.path,
      );

      expect(
        resultDisabled.exitCode,
        0,
        reason:
            'dart build cli (disabled treeshaking) failed.\nstdout:\n${resultDisabled.stdout}\nstderr:\n${resultDisabled.stderr}',
      );

      // Verify link hook logged that treeshaking was disabled via user define
      expect(
        resultDisabled.stdout.toString(),
        contains('webcrypto: Treeshaking is disabled via user define'),
        reason: 'Link hook did not recognize disable_treeshaking flag.',
      );
    } finally {
      if (tempDirTreeshaken.existsSync()) {
        tempDirTreeshaken.deleteSync(recursive: true);
      }
      if (tempDirDisabled.existsSync()) {
        tempDirDisabled.deleteSync(recursive: true);
      }
    }
  });
}

File? _findDynamicLibrary(List<Directory> searchDirs) {
  for (final dir in searchDirs) {
    if (dir.existsSync()) {
      final files = dir
          .listSync(recursive: true)
          .whereType<File>()
          .where(
            (f) => RegExp(r'(lib)?webcrypto\.(dll|dylib|so)$').hasMatch(f.path),
          );
      if (files.isNotEmpty) {
        return files.first;
      }
    }
  }
  return null;
}
