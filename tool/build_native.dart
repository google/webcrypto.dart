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

import 'package:args/args.dart';
import 'package:code_assets/code_assets.dart';
import 'package:native_toolchain_cmake/native_toolchain_cmake.dart';

Future<void> main(List<String> args) async {
  final parser = ArgParser()
    ..addOption(
      'target-os',
      help:
          'The target operating system (e.g. linux, macos, windows, android, ios).',
      mandatory: true,
      allowed: OS.values.map((os) => os.name).toList(),
    )
    ..addOption(
      'target-architecture',
      help: 'The target architecture (e.g. x64, arm64, arm, ia32, riscv64).',
      mandatory: true,
      allowed: Architecture.values.map((arch) => arch.name).toList(),
    )
    ..addOption(
      'output-dir',
      help:
          'The directory where build artifacts and installation will be output.',
      mandatory: true,
    );

  ArgResults argResults;
  try {
    argResults = parser.parse(args);
  } catch (e) {
    stderr.writeln('Error: $e\n');
    stderr.writeln('Usage:\n${parser.usage}');
    exit(64);
  }

  final targetOS = OS.fromString(argResults.option('target-os')!);
  final targetArch = Architecture.fromString(
    argResults.option('target-architecture')!,
  );
  final outputDirectory = Directory(
    argResults.option('output-dir')!,
  ).absolute.uri;

  final packageRoot = Directory.current.uri;
  final installDir = outputDirectory.resolve('install/');
  final sourceDir = packageRoot.resolve('src/');

  if (!Directory.fromUri(sourceDir).existsSync()) {
    stderr.writeln(
      'Error: Source directory does not exist at ${sourceDir.toFilePath()}',
    );
    exit(66);
  }

  final builder = CMakeBuilder.create(
    name: 'webcrypto',
    sourceDir: sourceDir,
    defines: {
      'CMAKE_BUILD_TYPE': 'Release',
      'CMAKE_INSTALL_PREFIX': installDir.toFilePath(),
    },
    targets: ['install'],
  );

  await builder.runStandalone(
    outputDirectory: outputDirectory,
    targetOS: targetOS,
    targetArchitecture: targetArch,
    packageRoot: packageRoot,
  );
}
