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
import 'package:crypto/crypto.dart' show sha256;
import 'package:hooks/hooks.dart';
import 'package:native_toolchain_cmake/native_toolchain_cmake.dart';
import 'package:webcrypto/src/hook_helpers/hashes.dart'
    show fileHashes, releaseVersion;

const _assetName = 'webcrypto.dart';

enum BuildModeEnum { fetch, build, local }

class BuildOptions {
  final BuildModeEnum buildMode;
  final Uri? localPath;

  BuildOptions({required this.buildMode, this.localPath});

  factory BuildOptions.fromDefines(HookInputUserDefines defines) {
    return BuildOptions(
      buildMode: BuildModeEnum.values.firstWhere(
        (element) => element.name == defines['buildMode'],
        orElse: () => BuildModeEnum.fetch,
      ),
      localPath: defines.path('localPath'),
    );
  }

  @override
  String toString() =>
      'BuildOptions(buildMode: $buildMode, localPath: $localPath)';
}

Future<void> main(List<String> args) async {
  await build(args, (input, output) async {
    // Skip build for non-code targets (e.g. web builds via flutter drive).
    if (!input.config.buildCodeAssets) {
      stdout.writeln(
        'webcrypto: skipping native asset build (code assets not requested).',
      );
      return;
    }

    final buildOptions = BuildOptions.fromDefines(input.userDefines);
    stdout.writeln('webcrypto: build options: $buildOptions');

    switch (buildOptions.buildMode) {
      case BuildModeEnum.fetch:
        await _fetchPrebuiltBinary(input, output);
      case BuildModeEnum.build:
        await _buildLocalCMake(input, output);
      case BuildModeEnum.local:
        await _useLocalBinary(input, output, buildOptions.localPath);
    }
    output.dependencies.add(input.packageRoot.resolve('pubspec.yaml'));
  });
}

Future<void> _fetchPrebuiltBinary(
  BuildInput input,
  BuildOutputBuilder output,
) async {
  final targetOS = input.config.code.targetOS;
  final targetArch = input.config.code.targetArchitecture;
  final dylibFileName = targetOS.dylibFileName('webcrypto');

  final targetTriple = '${targetOS.name}-${targetArch.name}';
  final expectedHash = fileHashes[targetTriple];

  if (expectedHash == null || expectedHash.isEmpty) {
    stdout.writeln(
      'webcrypto: no prebuilt binary hash registered for $targetTriple, falling back to building from source.',
    );
    await _buildLocalCMake(input, output);
    return;
  }

  final assetName = 'webcrypto-$targetTriple-$dylibFileName';
  final binaryUrl = Uri.parse(
    'https://github.com/google/webcrypto.dart/releases/download/v$releaseVersion/$assetName',
  );

  stdout.writeln('webcrypto: fetching prebuilt binary from $binaryUrl...');

  final client = HttpClient();
  try {
    final request = await client.getUrl(binaryUrl);
    final response = await request.close();
    if (response.statusCode != 200) {
      throw BuildError(
        message:
            'Failed to fetch prebuilt webcrypto binary from $binaryUrl (HTTP ${response.statusCode}).\n'
            'To build webcrypto locally from source instead, set `buildMode: build` in your pubspec.yaml under `hooks.user_defines.webcrypto`.',
      );
    }

    final bytes = await response.fold<List<int>>([], (a, b) => a..addAll(b));
    final actualHash = sha256.convert(bytes).toString();

    if (actualHash != expectedHash) {
      throw BuildError(
        message:
            'SHA256 hash mismatch for prebuilt binary $assetName.\n'
            'Expected: $expectedHash\n'
            'Actual:   $actualHash\n'
            'To build webcrypto locally from source instead, set `buildMode: build` in your pubspec.yaml under `hooks.user_defines.webcrypto`.',
      );
    }

    stdout.writeln('webcrypto: verified SHA256 checksum ($actualHash).');

    final libraryFile = File.fromUri(
      input.outputDirectory.resolve(dylibFileName),
    );
    await libraryFile.writeAsBytes(bytes);

    output.assets.code.add(
      CodeAsset(
        package: input.packageName,
        name: _assetName,
        linkMode: DynamicLoadingBundled(),
        file: libraryFile.uri,
      ),
    );
  } finally {
    client.close();
  }
}

Future<void> _useLocalBinary(
  BuildInput input,
  BuildOutputBuilder output,
  Uri? localPath,
) async {
  if (localPath == null) {
    throw BuildError(
      message:
          'buildMode is set to `local`, but `localPath` was not specified under `hooks.user_defines.webcrypto`.',
    );
  }
  final file = File.fromUri(localPath);
  if (!file.existsSync()) {
    throw BuildError(
      message:
          'Specified local binary does not exist at ${localPath.toFilePath()}',
    );
  }
  final dylibFileName = input.config.code.targetOS.dylibFileName('webcrypto');
  final destFile = File.fromUri(input.outputDirectory.resolve(dylibFileName));
  await file.copy(destFile.path);

  output.assets.code.add(
    CodeAsset(
      package: input.packageName,
      name: _assetName,
      linkMode: DynamicLoadingBundled(),
      file: destFile.uri,
    ),
  );
  output.dependencies.add(localPath);
}

Future<void> _buildLocalCMake(
  BuildInput input,
  BuildOutputBuilder output,
) async {
  final packageRoot = input.packageRoot;
  final installDir = input.outputDirectory.resolve('install/');
  final sourceDir = packageRoot.resolve('src/');

  stdout.writeln(
    'webcrypto: building native asset with CMake for '
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
