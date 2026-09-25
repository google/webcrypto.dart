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
const _libraryName = 'webcrypto';
const _buildFromSourceDefine = 'build_from_source';

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
    final prebuiltAsset = input.prebuiltAsset;

    if (!input.userDefines.buildFromSource && prebuiltAsset.existsSync()) {
      stdout.writeln(
        'webcrypto: using prebuilt native asset for '
        '${input.targetName}.',
      );
      output.assets.code.add(
        CodeAsset(
          package: input.packageName,
          name: _assetName,
          linkMode: DynamicLoadingBundled(),
          file: prebuiltAsset.uri,
        ),
      );
      output.dependencies.add(prebuiltAsset.uri);
      return;
    }

    stdout.writeln(
      'webcrypto: building native asset for '
      '${input.targetName}.',
    );

    final builder = CMakeBuilder.create(
      name: _libraryName,
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

extension on BuildInput {
  File get prebuiltAsset {
    final libraryFileName = config.code.targetOS.dylibFileName(_libraryName);
    return File.fromUri(
      packageRoot.resolve('prebuilt/$targetName/$libraryFileName'),
    );
  }

  String get targetName {
    final code = config.code;
    final os = code.targetOS;
    final arch = code.targetArchitecture;
    if (os == OS.iOS) {
      return '${os.name}-${code.iOS.targetSdk.type}-${arch.name}';
    }
    return '${os.name}-${arch.name}';
  }
}

extension on HookInputUserDefines {
  bool get buildFromSource => this[_buildFromSourceDefine] == true;
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
