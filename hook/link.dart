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

import 'package:code_assets/code_assets.dart'
    show CodeAsset, OS, HookConfigCodeConfig, LinkInputCodeAssets;
import 'package:hooks/hooks.dart' show link;
import 'package:logging/logging.dart' show Level, Logger;
import 'package:native_toolchain_c/native_toolchain_c.dart'
    show CLinker, LinkerOptions;
import 'package:record_use/record_use.dart' as record_use;

/// Run the linker to turn a static library into a treeshaken dynamic library.
Future<void> main(List<String> args) async {
  await link(args, (input, output) async {
    stdout.writeln('webcrypto: start link hook');

    final CodeAsset staticLib;
    try {
      staticLib = input.assets.code.firstWhere(
        (asset) => asset.id == 'package:webcrypto/webcrypto.dart',
      );
    } catch (e) {
      // No static library provided, assume a dynamic library was already bundled.
      stdout.writeln('webcrypto: no static asset found for linking, skipping.');
      return;
    }

    final recordedUses = input.recordedUses;
    Iterable<String>? usedSymbols;

    if (recordedUses == null) {
      stdout.writeln(
        'webcrypto: --enable-experiment=record-use not active; linking all symbols.',
      );
    } else {
      usedSymbols = recordedUses.calls.keys
          .where(
            (id) =>
                id.library ==
                    const record_use.Library(
                      'package:webcrypto/src/boringssl/bindings/generated_bindings.dart',
                    ) ||
                id.library ==
                    const record_use.Library(
                      'package:webcrypto/src/third_party/boringssl/generated_bindings.dart',
                    ),
          )
          .map((id) => id.name)
          .where((methodName) => methodName.startsWith('_'))
          .map((methodName) => methodName.substring(1));
    }

    stdout.writeln('''
webcrypto treeshaking symbols:
  ${usedSymbols?.join('\n') ?? 'All symbols preserved.'}
''');

    await CLinker.library(
      name: 'webcrypto',
      packageName: input.packageName,
      assetName: 'webcrypto.dart',
      sources: [staticLib.file!.toFilePath()],
      libraries: switch (input.config.code.targetOS) {
        OS.windows => const ['MSVCRT', 'ws2_32', 'userenv', 'ntdll', 'bcrypt'],
        OS.android => const ['m'],
        _ => const [],
      },
      linkerOptions: LinkerOptions.treeshake(symbolsToKeep: usedSymbols),
    ).run(
      input: input,
      output: output,
      logger: Logger('webcrypto_linker')
        ..level = Level.ALL
        ..onRecord.listen((record) => stdout.writeln(record.message)),
    );
  });
}
