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

import 'dart:io';
import 'package:yaml/yaml.dart';

/// Generate matching symbols table for Dart and C.
///
/// See: `src/symbols.yaml` for documentation on why and how this works.
Future<void> main() async {
  final rootUri = Platform.script.resolve('../');
  print('Generating matching symbols table in Dart and C:');

  // Load src/symbols.yaml
  print(' - Loading src/symbols.yaml');
  final symbolsYamlUri = rootUri.resolve('src/symbols.yaml');
  final symbols = loadYaml(
    await File.fromUri(symbolsYamlUri).readAsString(),
    sourceUrl: symbolsYamlUri,
  );
  print(' - Found ${symbols.length} symbols');

  // Generate src/symbols.generated.c
  print(' - Writing src/symbols.generated.c');
  await File.fromUri(rootUri.resolve('src/symbols.generated.c')).writeAsString([
    '/*',
    ' * Copyright 2020 Google LLC',
    ' *',
    ' * Licensed under the Apache License, Version 2.0 (the "License");',
    ' * you may not use this file except in compliance with the License.',
    ' * You may obtain a copy of the License at',
    ' *',
    ' *      http://www.apache.org/licenses/LICENSE-2.0',
    ' *',
    ' * Unless required by applicable law or agreed to in writing, software',
    ' * distributed under the License is distributed on an "AS IS" BASIS,',
    ' * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.',
    ' * See the License for the specific language governing permissions and',
    ' * limitations under the License.',
    ' */',
    '',
    '// **GENERATED FILE DO NOT MODIFY**',
    '//',
    '// This file is generated from `src/symbols.yaml` using:',
    '// `tool/generate_symbols_table.dart`',
    '',
    '#include "symbols.h"',
    '',
    'void* _webcrypto_symbol_table[] = {',
    symbols.map((s) => '    (void*)&$s,').join('\n'),
    '};',
    ''
  ].join('\n'));

  // Generate lib/src/boringssl/lookup/symbols.generated.dart
  print(' - Writing lib/src/boringssl/lookup/symbols.generated.dart');
  final generatedDart = 'lib/src/boringssl/lookup/symbols.generated.dart';
  await File.fromUri(rootUri.resolve(generatedDart)).writeAsString([
    '// Copyright 2020 Google LLC',
    '//',
    '// Licensed under the Apache License, Version 2.0 (the "License");',
    '// you may not use this file except in compliance with the License.',
    '// You may obtain a copy of the License at',
    '//',
    '//      http://www.apache.org/licenses/LICENSE-2.0',
    '//',
    '// Unless required by applicable law or agreed to in writing, software',
    '// distributed under the License is distributed on an "AS IS" BASIS,',
    '// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.',
    '// See the License for the specific language governing permissions and',
    '// limitations under the License.',
    '',
    '/// **GENERATED FILE DO NOT MODIFY**',
    '///',
    '/// This file is generated from `src/symbols.yaml` using:',
    '/// `tool/generate_symbols_table.dart`',
    'library symbols.generated;',
    '',
    '/// BoringSSL symbols used in `package:webcrypto`.',
    'enum Sym {',
    symbols.map((s) => '  $s,').join('\n'),
    '}',
    '',
    'const _SymName = [',
    symbols.map((s) => '  \'$s\',').join('\n'),
    '];',
    '',
    'extension SymName on Sym {',
    '  /// Get name of symbol in `libcrypto.so` from BoringSSL.',
    '  String get name {',
    '    return _SymName[index];',
    '  }',
    '}',
    '',
    'Sym symFromString(String string) => Sym.values[_SymName.indexOf(string)];',
    '',
  ].join('\n'));

  print('Done');
}
