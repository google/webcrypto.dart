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

// ignore_for_file: avoid_print

import 'dart:io';
import 'dart:convert';

/// Build a `[lib]webcrypto.{so|dll|dylib}` in ´.dart_tool/webcrypto/` for the
/// current root project.
///
/// The lookup compatibility path can find this file in legacy direct-script
/// environments that do not execute package build hooks. Supported Dart and
/// Flutter SDKs build and bundle the library automatically; new projects
/// should not invoke this command.
void main() async {
  // Assumed package root
  final root = Directory.current.uri;
  print('Building with assumed project root in:');
  print(root.toFilePath());

  // Assumed package_config.json
  final packageConfigFile = File.fromUri(
    root.resolve('.dart_tool/package_config.json'),
  );
  dynamic packageConfig;
  try {
    packageConfig = json.decode(await packageConfigFile.readAsString());
  } on FileSystemException {
    print('Missing .dart_tool/package_config.json');
    print('Run `flutter pub get` first.');
    exit(1);
  } on FormatException {
    print('Invalid .dart_tool/package_config.json');
    print('Run `flutter pub get` first.');
    exit(1);
  }

  // Determine the source path of package:webcrypto in the PUB_CACHE
  final pkg = (packageConfig['packages'] ?? []).firstWhere(
    (e) => e['name'] == 'webcrypto',
    orElse: () => null,
  );
  if (pkg == null) {
    print('dependency on package:webcrypto is required');
    exit(1);
  }
  final webcryptoRoot = packageConfigFile.uri.resolve(pkg['rootUri'] ?? '');
  print('Using package:webcrypto from ${webcryptoRoot.toFilePath()}');

  print('Generating build system with cmake');
  final generate = await Process.start(
    'cmake',
    [
      '-S',
      Directory(_joinPaths(webcryptoRoot.toFilePath(), 'src')).path,
      '-B',
      root.resolve('.dart_tool/webcrypto').toFilePath(),
    ],
    runInShell: true,
    mode: ProcessStartMode.inheritStdio,
    includeParentEnvironment: true,
  );
  if ((await generate.exitCode) != 0) {
    print('Generating with cmake failed, ensure you have dependencies!');
    exit(1);
  }

  print('Building webcrypto target with cmake');
  final build = await Process.start(
    'cmake',
    [
      '--build',
      root.resolve('.dart_tool/webcrypto').toFilePath(),
      '--target',
      'webcrypto',
    ],
    runInShell: true,
    mode: ProcessStartMode.inheritStdio,
    includeParentEnvironment: true,
  );
  if ((await build.exitCode) != 0) {
    print('Building with cmake failed, ensure you have dependencies!');
    exit(1);
  }

  print('Package webcrypto legacy fallback configured for this project.');
  print('Supported Dart/Flutter SDKs run hook/build.dart automatically;');
  print('this command is only for legacy direct-script environments.');
}

/// Join paths without duplicate path separators.
String _joinPaths(String prefix, String suffix) {
  if (!prefix.endsWith(Platform.pathSeparator)) {
    prefix += Platform.pathSeparator;
  }
  return prefix + suffix;
}
