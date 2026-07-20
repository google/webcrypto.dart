// Copyright 2026 The webcrypto.dart authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0

/// Builds package:webcrypto's vendored BoringSSL wrapper as a Dart Native
/// Asset on every supported native target.
///
/// Web builds do not request code assets, so this hook intentionally does
/// nothing for them. Native builds use a content-addressed, process-locked
/// cache because compiling BoringSSL for every hook invocation is expensive.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:code_assets/code_assets.dart';
import 'package:crypto/crypto.dart';
import 'package:hooks/hooks.dart';
import 'package:logging/logging.dart';
import 'package:native_toolchain_cmake/native_toolchain_cmake.dart';
import 'package:path/path.dart' as p;

const _assetName = 'src/boringssl/lookup/lookup.dart';
const _cacheSchema = 'webcrypto-native-assets-v2';

void main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) return;

    final code = input.config.code;
    _validateTarget(code.targetOS, code.targetArchitecture);

    final logger = Logger.root
      ..level = Level.WARNING
      ..onRecord.listen((record) => stderr.writeln(record.message));

    final nativeInputs = await _collectNativeInputs(input.packageRoot);
    output.dependencies.addAll(nativeInputs.map((input) => input.uri));

    final defines = <String, String>{
      'WEBCRYPTO_BORINGSSL_PLATFORM': _boringSslPlatform(code.targetOS),
      'WEBCRYPTO_BORINGSSL_ARCH': _boringSslArchitecture(
        code.targetArchitecture,
      ),
      'CMAKE_POSITION_INDEPENDENT_CODE': 'ON',
    };
    final buildKey = await _computeBuildKey(
      code: code,
      defines: defines,
      inputs: nativeInputs,
    );
    final libraryFileName = _libraryFileName(code.targetOS);
    final cacheDir = _cacheDirectory(buildKey);
    final cachedLibrary = File(p.join(cacheDir.path, libraryFileName));
    final cachedDigest = File('${cachedLibrary.path}.sha256');
    final lockFile = File('${cacheDir.path}.lock');

    if (!await _validLibrary(cachedLibrary, cachedDigest)) {
      await _withExclusiveLock(lockFile, () async {
        if (await _validLibrary(cachedLibrary, cachedDigest)) return;
        await _buildIntoCache(
          input: input,
          output: output,
          defines: defines,
          cacheDir: cacheDir,
          cachedLibrary: cachedLibrary,
          cachedDigest: cachedDigest,
          libraryFileName: libraryFileName,
          logger: logger,
        );
      });
    }

    if (!await _validLibrary(cachedLibrary, cachedDigest)) {
      throw StateError(
        'webcrypto cache publication failed for ${code.targetOS.name}/'
        '${code.targetArchitecture.name}: ${cachedLibrary.path}',
      );
    }

    final publishedLibrary = await _publish(
      cachedLibrary,
      input.outputDirectory,
      libraryFileName,
    );
    output.assets.code.add(
      CodeAsset(
        package: input.packageName,
        name: _assetName,
        linkMode: DynamicLoadingBundled(),
        file: publishedLibrary.uri,
      ),
    );
  });
}

Future<void> _buildIntoCache({
  required BuildInput input,
  required BuildOutputBuilder output,
  required Map<String, String> defines,
  required Directory cacheDir,
  required File cachedLibrary,
  required File cachedDigest,
  required String libraryFileName,
  required Logger logger,
}) async {
  await cacheDir.create(recursive: true);
  final buildDir = Directory(p.join(cacheDir.path, 'build'));
  if (await buildDir.exists()) await buildDir.delete(recursive: true);
  await buildDir.create(recursive: true);

  final code = input.config.code;
  try {
    final builder = CMakeBuilder.create(
      name: 'webcrypto',
      sourceDir: input.packageRoot.resolve('src/'),
      outDir: buildDir.uri,
      defines: defines,
      targets: const ['webcrypto'],
      buildLocal: false,
      parallelUseAllProcessors: true,
      logger: logger,
    );
    await builder.run(input: input, output: output, logger: logger);

    final builtLibrary = await _findLibrary(buildDir, libraryFileName);
    if (builtLibrary == null || !await _validNonEmptyFile(builtLibrary)) {
      throw StateError(
        'CMake reported success but did not produce a non-empty '
        '$libraryFileName. Build output:\n${await _listBuildOutput(buildDir)}',
      );
    }

    // Publish library and digest under the exclusive build-key lock. The
    // digest lets later invocations reject truncated/corrupt cache entries.
    final temporaryLibrary = File(
      p.join(cacheDir.path, '.$libraryFileName.$pid.tmp'),
    );
    final temporaryDigest = File('${temporaryLibrary.path}.sha256');
    if (await temporaryLibrary.exists()) await temporaryLibrary.delete();
    if (await temporaryDigest.exists()) await temporaryDigest.delete();
    await builtLibrary.copy(temporaryLibrary.path);
    final digest = await _sha256File(temporaryLibrary);
    await temporaryDigest.writeAsString('$digest\n', flush: true);
    if (await cachedLibrary.exists()) await cachedLibrary.delete();
    await temporaryLibrary.rename(cachedLibrary.path);
    if (await cachedDigest.exists()) await cachedDigest.delete();
    await temporaryDigest.rename(cachedDigest.path);
  } catch (error, stackTrace) {
    throw StateError(
      'Failed to build package:webcrypto for ${code.targetOS.name}/'
      '${code.targetArchitecture.name} using the Native Assets target '
      'toolchain. Build directory: ${buildDir.path}. Error: $error\n'
      '$stackTrace',
    );
  }
}

void _validateTarget(OS os, Architecture architecture) {
  final supported = switch (os) {
    OS.android => const {
      Architecture.arm,
      Architecture.arm64,
      Architecture.ia32,
      Architecture.x64,
    },
    OS.iOS => const {Architecture.arm64, Architecture.x64},
    OS.linux => const {Architecture.arm64, Architecture.x64},
    OS.macOS => const {Architecture.arm64, Architecture.x64},
    OS.windows => const {
      Architecture.arm64,
      Architecture.ia32,
      Architecture.x64,
    },
    _ => const <Architecture>{},
  };
  if (!supported.contains(architecture)) {
    throw UnsupportedError(
      'package:webcrypto does not support Native Assets target '
      '${os.name}/${architecture.name}. Supported architectures for '
      '${os.name}: ${supported.map((value) => value.name).join(', ')}.',
    );
  }
}

String _boringSslPlatform(OS os) => switch (os) {
  OS.android || OS.linux => 'linux',
  OS.iOS || OS.macOS => 'apple',
  OS.windows => 'win',
  _ => throw UnsupportedError('package:webcrypto does not support ${os.name}.'),
};

String _boringSslArchitecture(Architecture architecture) =>
    switch (architecture) {
      Architecture.arm => 'arm',
      Architecture.arm64 => 'aarch64',
      Architecture.ia32 => 'x86',
      Architecture.x64 => 'x86_64',
      _ => throw UnsupportedError(
        'package:webcrypto does not support ${architecture.name}.',
      ),
    };

String _libraryFileName(OS os) => switch (os) {
  OS.windows => 'webcrypto.dll',
  OS.iOS || OS.macOS => 'libwebcrypto.dylib',
  OS.android || OS.linux => 'libwebcrypto.so',
  _ => throw UnsupportedError('package:webcrypto does not support ${os.name}.'),
};

final class _NativeInput {
  const _NativeInput(this.relativePath, this.uri);

  final String relativePath;
  final Uri uri;
}

Future<List<_NativeInput>> _collectNativeInputs(Uri packageRoot) async {
  final packagePath = Directory.fromUri(packageRoot).path;
  final roots = [
    packageRoot.resolve('src/'),
    packageRoot.resolve('third_party/boringssl/'),
    packageRoot.resolve('hook/'),
  ];
  final inputs = <_NativeInput>[
    _NativeInput('pubspec.yaml', packageRoot.resolve('pubspec.yaml')),
  ];

  for (final root in roots) {
    final directory = Directory.fromUri(root);
    if (!await directory.exists()) {
      throw StateError('Required webcrypto native input is missing: $root');
    }
    await for (final entity in directory.list(
      recursive: true,
      followLinks: false,
    )) {
      if (entity is! File) continue;
      final relative = p.relative(entity.path, from: packagePath);
      if (p
          .split(relative)
          .any((part) => part == 'build' || part == '.dart_tool')) {
        continue;
      }
      if (_isNativeInput(entity.path)) {
        inputs.add(_NativeInput(relative, entity.uri));
      }
    }
  }

  inputs.sort((a, b) => a.relativePath.compareTo(b.relativePath));
  return inputs;
}

bool _isNativeInput(String path) {
  final extension = p.extension(path).toLowerCase();
  return const {
        '.c',
        '.cc',
        '.cpp',
        '.h',
        '.inc',
        '.s',
        '.asm',
        '.cmake',
        '.dart',
        '.yaml',
      }.contains(extension) ||
      p.basename(path) == 'CMakeLists.txt';
}

Future<String> _computeBuildKey({
  required CodeConfig code,
  required Map<String, String> defines,
  required List<_NativeInput> inputs,
}) async {
  final bytes = BytesBuilder(copy: false);

  void addText(String value) {
    bytes.add(utf8.encode(value));
    bytes.addByte(0);
  }

  addText(_cacheSchema);
  addText('os=${code.targetOS.name}');
  addText('arch=${code.targetArchitecture.name}');
  addText('link=${code.linkModePreference}');
  final compiler = code.cCompiler;
  if (compiler != null) {
    for (final tool in <String, Uri>{
      'cc': compiler.compiler,
      'ld': compiler.linker,
      'ar': compiler.archiver,
    }.entries) {
      addText('${tool.key}=${tool.value}');
      if (tool.value.scheme == 'file') {
        final file = File.fromUri(tool.value);
        if (await file.exists()) {
          final stat = await file.stat();
          addText(
            '${tool.key}Stat=${stat.size}:'
            '${stat.modified.microsecondsSinceEpoch}',
          );
        }
      }
    }
  }
  if (code.targetOS == OS.android) {
    addText('androidApi=${code.android.targetNdkApi}');
  } else if (code.targetOS == OS.iOS) {
    addText('iosSdk=${code.iOS.targetSdk}');
    addText('iosVersion=${code.iOS.targetVersion}');
  } else if (code.targetOS == OS.macOS) {
    addText('macosVersion=${code.macOS.targetVersion}');
  }
  for (final define
      in defines.entries.toList()..sort((a, b) => a.key.compareTo(b.key))) {
    addText('define:${define.key}=${define.value}');
  }
  for (final input in inputs) {
    addText('file:${input.relativePath}');
    final file = File.fromUri(input.uri);
    if (!await file.exists()) {
      throw StateError('Native build input disappeared: ${input.uri}');
    }
    await for (final chunk in file.openRead()) {
      bytes.add(chunk);
    }
    bytes.addByte(0);
  }

  return sha256.convert(bytes.takeBytes()).toString();
}

Directory _cacheDirectory(String buildKey) {
  final xdg = Platform.environment['XDG_CACHE_HOME'];
  if (xdg != null && xdg.isNotEmpty) {
    return Directory(p.join(xdg, 'webcrypto.dart', buildKey));
  }
  if (Platform.isWindows) {
    final localAppData = Platform.environment['LOCALAPPDATA'];
    if (localAppData != null && localAppData.isNotEmpty) {
      return Directory(
        p.join(localAppData, 'webcrypto.dart', 'Cache', buildKey),
      );
    }
  }
  final home =
      Platform.environment['HOME'] ??
      Platform.environment['USERPROFILE'] ??
      (throw StateError(
        'Cannot locate the webcrypto build cache: HOME, USERPROFILE, and '
        'XDG_CACHE_HOME are all unset.',
      ));
  return Directory(p.join(home, '.cache', 'webcrypto.dart', buildKey));
}

Future<void> _withExclusiveLock(
  File lockFile,
  Future<void> Function() body,
) async {
  await lockFile.parent.create(recursive: true);
  final randomAccessFile = await lockFile.open(mode: FileMode.append);
  try {
    await randomAccessFile.lock(FileLock.blockingExclusive);
    try {
      await body();
    } finally {
      await randomAccessFile.unlock();
    }
  } finally {
    await randomAccessFile.close();
  }
}

Future<bool> _validLibrary(File library, File digestFile) async {
  if (!await _validNonEmptyFile(library) || !await digestFile.exists()) {
    return false;
  }
  final expected = (await digestFile.readAsString()).trim();
  if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(expected)) return false;
  return await _sha256File(library) == expected;
}

Future<bool> _validNonEmptyFile(File file) async =>
    await file.exists() && await file.length() > 0;

Future<String> _sha256File(File file) async {
  final digestSink = _DigestSink();
  final input = sha256.startChunkedConversion(digestSink);
  await for (final chunk in file.openRead()) {
    input.add(chunk);
  }
  input.close();
  return digestSink.value.toString();
}

final class _DigestSink implements Sink<Digest> {
  late Digest value;

  @override
  void add(Digest data) => value = data;

  @override
  void close() {}
}

Future<File?> _findLibrary(Directory root, String fileName) async {
  final candidates = <File>[];
  await for (final entity in root.list(recursive: true, followLinks: false)) {
    if (entity is File && p.basename(entity.path) == fileName) {
      candidates.add(entity);
    }
  }
  if (candidates.isEmpty) return null;
  candidates.sort((a, b) {
    final releaseA = p.split(a.path).contains('Release') ? 0 : 1;
    final releaseB = p.split(b.path).contains('Release') ? 0 : 1;
    final byConfiguration = releaseA.compareTo(releaseB);
    return byConfiguration != 0 ? byConfiguration : a.path.compareTo(b.path);
  });
  return candidates.first;
}

Future<File> _publish(
  File cachedLibrary,
  Uri outputDirectory,
  String libraryFileName,
) async {
  final output = Directory.fromUri(outputDirectory);
  await output.create(recursive: true);
  final destination = File(p.join(output.path, libraryFileName));
  final temporary = File('${destination.path}.$pid.tmp');
  if (await temporary.exists()) await temporary.delete();
  await cachedLibrary.copy(temporary.path);
  if (await destination.exists()) await destination.delete();
  return temporary.rename(destination.path);
}

Future<String> _listBuildOutput(Directory directory) async {
  final lines = <String>[];
  if (!await directory.exists()) return '  (output directory does not exist)';
  await for (final entity in directory.list(
    recursive: true,
    followLinks: false,
  )) {
    lines.add('  ${entity.path}');
    if (lines.length == 100) {
      lines.add('  (truncated)');
      break;
    }
  }
  return lines.join('\n');
}
