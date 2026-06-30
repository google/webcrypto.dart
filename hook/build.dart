// Copyright 2025 Google LLC
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

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';
import 'package:native_toolchain_cmake/native_toolchain_cmake.dart';

const _assetName = 'webcrypto.dart';

Future<void> main(List<String> args) async {
  await build(args, (input, output) async {
    // Skip build for non-code targets (e.g. web builds via flutter drive).
    if (!input.config.buildCodeAssets) {
      stdout.writeln(
        'webcrypto: skipping native asset build (code assets not requested).',
      );
      return;
    }

    final packageRoot = input.packageRoot;
    final installDir = input.outputDirectory.resolve('install/');
    final sourceDir = packageRoot.resolve('src/');

    stdout.writeln(
      'webcrypto: building native asset for '
      '${input.config.code.targetOS}-${input.config.code.targetArchitecture}.',
    );

    final builder = CMakeBuilder.create(
      name: 'webcrypto',
      sourceDir: sourceDir,
      defines: {
        'CMAKE_BUILD_TYPE': 'Release',
        'CMAKE_INSTALL_PREFIX': installDir.toFilePath(),
      },
      targets: ['install'],
    );

    await builder.run(input: input, output: output);

    final assets = await output.findAndAddCodeAssets(
      input,
      outDir: installDir,
      names: {r'(lib)?webcrypto\.(dll|dylib|so)': _assetName},
      regExp: true,
    );
    if (assets.isEmpty) {
      throw BuildError(
        message:
            'Failed to locate built webcrypto dynamic library in '
            '${installDir.toFilePath()}',
      );
    }

    output.dependencies.addAll(_buildDependencies(packageRoot));
  });
}

final _buildDependencyExtensions = {
  '.S',
  '.asm',
  '.c',
  '.cc',
  '.cmake',
  '.cpp',
  '.h',
};

Iterable<Uri> _buildDependencies(Uri packageRoot) sync* {
  yield* _filesForBuild(Directory.fromUri(packageRoot.resolve('src/')));
  yield* _filesForBuild(
    Directory.fromUri(packageRoot.resolve('third_party/boringssl/')),
  );
}

Iterable<Uri> _filesForBuild(Directory root) sync* {
  if (!root.existsSync()) {
    return;
  }

  for (final entity in root.listSync(recursive: true, followLinks: false)) {
    if (entity is! File) {
      continue;
    }
    if (!_buildDependencyExtensions.any(entity.uri.path.endsWith)) {
      continue;
    }
    yield entity.uri;
  }
}
