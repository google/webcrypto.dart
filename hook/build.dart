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

    final buildDir = Directory.fromUri(input.outputDirectory);
    buildDir.createSync(recursive: true);

    final packageRoot = Directory.fromUri(input.packageRoot);
    final configureArgs = [
      '-S',
      Directory.fromUri(packageRoot.uri.resolve('src/')).path,
      '-B',
      buildDir.path,
    ];

    final systemProcessor = _cmakeSystemProcessor(targetArch);
    if (systemProcessor != null) {
      configureArgs.add('-DCMAKE_SYSTEM_PROCESSOR=$systemProcessor');
    }

    // Ensure generated artefacts go to the requested architecture where needed.
    switch (targetOs) {
      case OS.macOS:
        final cmakeArch = _cmakeArchitectureFlag(targetArch);
        if (cmakeArch != null) {
          configureArgs.add('-DCMAKE_OSX_ARCHITECTURES=$cmakeArch');
        }
        break;
      case OS.windows:
        final vsArch = _visualStudioArchitecture(targetArch);
        if (vsArch != null) {
          configureArgs.addAll(['-A', vsArch]);
        }
        break;
      default:
        break;
    }

    stdout.writeln(
      'webcrypto: configuring CMake in ${buildDir.path} for '
      '${targetOs.name}-${targetArch.name}',
    );
    await _runProcess(
      'cmake',
      configureArgs,
      workingDirectory: packageRoot.path,
    );

    final buildArgs = ['--build', buildDir.path, '--target', 'webcrypto'];
    if (targetOs == OS.windows) {
      buildArgs.addAll(['--config', 'Release']);
    }

    stdout.writeln(
      'webcrypto: building native library (cmake ${buildArgs.join(' ')})',
    );
    await _runProcess('cmake', buildArgs, workingDirectory: packageRoot.path);

    final libraryName = _libraryFileName(targetOs);
    final libraryFile = _resolveLibrary(buildDir, libraryName);
    if (libraryFile == null || !libraryFile.existsSync()) {
      throw BuildError(
        message:
            'Failed to locate built library $libraryName in ${buildDir.path}',
      );
    }

    stdout.writeln('webcrypto: emitting native asset ${libraryFile.path}');
    output.assets.code.add(
      CodeAsset(
        package: input.packageName,
        name: _assetName,
        linkMode: DynamicLoadingBundled(),
        file: libraryFile.absolute.uri,
      ),
    );

    for (final dependency in [
      packageRoot.uri.resolve('src/CMakeLists.txt'),
      packageRoot.uri.resolve('src/webcrypto.c'),
      packageRoot.uri.resolve('src/webcrypto.h'),
      packageRoot.uri.resolve('src/symbols.generated.c'),
      packageRoot.uri.resolve('third_party/boringssl/sources.cmake'),
    ]) {
      output.dependencies.add(dependency);
    }
  });
}

Future<void> _runProcess(
  String executable,
  List<String> arguments, {
  required String workingDirectory,
}) async {
  final Process process;
  try {
    process = await Process.start(
      executable,
      arguments,
      workingDirectory: workingDirectory,
      runInShell: true,
      includeParentEnvironment: true,
      mode: ProcessStartMode.inheritStdio,
    );
  } on ProcessException catch (e, stackTrace) {
    throw BuildError(
      message: 'Failed to start $executable: ${e.message}',
      wrappedException: e,
      wrappedTrace: stackTrace,
    );
  }
  final exitCode = await process.exitCode;
  if (exitCode != 0) {
    throw BuildError(message: 'Command $executable exited with $exitCode');
  }
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

String? _cmakeArchitectureFlag(Architecture architecture) {
  switch (architecture) {
    case Architecture.arm64:
      return 'arm64';
    case Architecture.x64:
      return 'x86_64';
    default:
      return null;
  }
}

String? _visualStudioArchitecture(Architecture architecture) {
  switch (architecture) {
    case Architecture.x64:
      return 'x64';
    default:
      return null;
  }
}

String? _cmakeSystemProcessor(Architecture architecture) {
  switch (architecture) {
    case Architecture.x64:
      return 'x86_64';
    case Architecture.arm64:
      return 'arm64';
    case Architecture.arm:
      return 'arm';
    case Architecture.ia32:
      return 'x86';
    default:
      return null;
  }
}

String _libraryFileName(OS targetOs) {
  return switch (targetOs) {
    OS.windows => 'webcrypto.dll',
    OS.macOS => 'libwebcrypto.dylib',
    _ => 'libwebcrypto.so',
  };
}

File? _resolveLibrary(Directory buildDir, String libraryName) {
  final primary = File.fromUri(buildDir.uri.resolve(libraryName));
  if (primary.existsSync()) {
    return primary;
  }

  // Handle multi-configuration generators (e.g. Visual Studio) where artefacts
  // may live in a configuration subdirectory such as `Release`.
  final releaseCandidate = File.fromUri(
    buildDir.uri.resolve('Release/$libraryName'),
  );
  if (releaseCandidate.existsSync()) {
    return releaseCandidate;
  }

  return null;
}
