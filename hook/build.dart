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
const _prebuiltRoot = 'prebuilt';
const _forceSourceBuildMarker = '.ci_force_source_build';

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
    final config = input.config.code;
    final installDir = input.outputDirectory.resolve('install/');
    final sourceDir = packageRoot.resolve('src/');
    final forceSourceBuild = _shouldForceSourceBuild(packageRoot);
    final prebuilt = forceSourceBuild
        ? null
        : _findPrebuiltAsset(packageRoot, config);

    if (forceSourceBuild) {
      stdout.writeln('webcrypto: forcing source build for CI validation.');
    }

    if (prebuilt != null) {
      stdout.writeln(
        'webcrypto: using prebuilt native asset for '
        '${config.targetOS}-${config.targetArchitecture}.',
      );

      final stagedPrebuilt = await _stagePrebuiltAsset(
        input: input,
        prebuilt: prebuilt,
      );
      output.assets.code.add(
        CodeAsset(
          package: input.packageName,
          name: _assetName,
          linkMode: DynamicLoadingBundled(),
          file: stagedPrebuilt,
        ),
      );
      output.dependencies.add(prebuilt);
      return;
    }

    stdout.writeln(
      'webcrypto: building native asset for '
      '${config.targetOS}-${config.targetArchitecture}.',
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

Uri? _findPrebuiltAsset(Uri packageRoot, CodeConfig config) {
  final fileName = config.targetOS.dylibFileName('webcrypto');
  final prebuilt = packageRoot.resolve(
    '$_prebuiltRoot/'
    '${config.targetOS.name}/'
    '${config.targetArchitecture.name}/'
    '$fileName',
  );
  return File.fromUri(prebuilt).existsSync() ? prebuilt : null;
}

bool _shouldForceSourceBuild(Uri packageRoot) =>
    File.fromUri(packageRoot.resolve(_forceSourceBuildMarker)).existsSync();

Future<Uri> _stagePrebuiltAsset({
  required BuildInput input,
  required Uri prebuilt,
}) async {
  final targetDir = input.outputDirectoryShared.resolve(
    '$_prebuiltRoot/'
    '${input.config.code.targetOS.name}/'
    '${input.config.code.targetArchitecture.name}/',
  );
  final targetDirectory = Directory.fromUri(targetDir);
  await targetDirectory.create(recursive: true);

  final fileName = prebuilt.pathSegments.last;
  final staged = targetDir.resolve(fileName);
  await File.fromUri(prebuilt).copy(staged.toFilePath());
  return staged;
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
