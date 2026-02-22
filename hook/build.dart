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

import 'dart:ffi';
import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';
import 'package:native_toolchain_cmake/native_toolchain_cmake.dart';

const _assetName = 'webcrypto.dart';

Future<void> main(List<String> args) async {
  await build(args, (input, output) async {
    final targetOs = input.config.code.targetOS;
    if (!_hostSupports(targetOs)) {
      stdout.writeln(
        'webcrypto: skipping native asset build for unsupported target OS '
        '$targetOs on host ${Platform.operatingSystem}.',
      );
      return;
    }

    final targetArch = input.config.code.targetArchitecture;
    if (!_hostSupportsArchitecture(targetArch)) {
      stdout.writeln(
        'webcrypto: skipping native asset build for unsupported target '
        'architecture $targetArch on host ${Abi.current()}.',
      );
      return;
    }

    final packageRoot = Directory.fromUri(input.packageRoot).uri;
    final installDir = input.outputDirectory.resolve('install/');
    final sourceDir = packageRoot.resolve('src/');

    final builder = CMakeBuilder.create(
      name: 'webcrypto',
      sourceDir: sourceDir,
      buildLocal: true,
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

    for (final dependency in [
      packageRoot.resolve('src/CMakeLists.txt'),
      packageRoot.resolve('src/webcrypto.c'),
      packageRoot.resolve('src/webcrypto.h'),
      packageRoot.resolve('src/symbols.generated.c'),
      packageRoot.resolve('third_party/boringssl/sources.cmake'),
    ]) {
      output.dependencies.add(dependency);
    }
  });
}

bool _hostSupports(OS target) {
  switch (target) {
    case OS.linux:
      return Platform.isLinux;
    case OS.macOS:
      return Platform.isMacOS;
    case OS.windows:
      return Platform.isWindows;
    default:
      return false;
  }
}

bool _hostSupportsArchitecture(Architecture targetArch) {
  switch (targetArch) {
    case Architecture.arm64:
      return const {
        Abi.androidArm64,
        Abi.fuchsiaArm64,
        Abi.iosArm64,
        Abi.linuxArm64,
        Abi.macosArm64,
        Abi.windowsArm64,
      }.contains(Abi.current());
    case Architecture.x64:
      return const {
        Abi.androidX64,
        Abi.fuchsiaX64,
        Abi.iosX64,
        Abi.linuxX64,
        Abi.macosX64,
        Abi.windowsX64,
      }.contains(Abi.current());
    default:
      return false;
  }
}
