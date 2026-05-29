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

// ignore_for_file: avoid_print

import 'dart:io';

import 'package:yaml/yaml.dart';

const _assetId = 'package:webcrypto/webcrypto.dart';
const _helperExports = <String>[
  'webcrypto_get_CBB_size',
  'webcrypto_get_EVP_PKEY_free_address',
];

final class _MethodBinding {
  final String name;
  final String returnType;
  final String params;
  final String args;
  final String nativeType;

  const _MethodBinding({
    required this.name,
    required this.returnType,
    required this.params,
    required this.args,
    required this.nativeType,
  });
}

Future<void> main() async {
  final rootUri = Platform.script.resolve('../');
  final symbolsYamlUri = rootUri.resolve('src/symbols.yaml');
  final bindingsUri = rootUri.resolve(
    'lib/src/third_party/boringssl/generated_bindings.dart',
  );
  final outputUri = rootUri.resolve(
    'lib/src/boringssl/lookup/direct_bindings.generated.dart',
  );
  final exportsUri = rootUri.resolve('src/webcrypto_exports.def');

  print('Generating direct bindings from ${symbolsYamlUri.pathSegments.last}:');
  final symbols = List<String>.from(
    loadYaml(
      await File.fromUri(symbolsYamlUri).readAsString(),
      sourceUrl: symbolsYamlUri,
    ),
  );
  print(' - Loaded ${symbols.length} symbol declarations');

  final thirdPartyBindings = await File.fromUri(bindingsUri).readAsString();
  final bindings = <_MethodBinding>[];

  for (final symbol in symbols) {
    final binding = _extractBinding(thirdPartyBindings, symbol);
    if (binding != null) {
      bindings.add(binding);
    } else {
      print(' - Skipping $symbol: no generated binding found');
    }
  }

  print(' - Writing ${outputUri.pathSegments.last} for ${bindings.length} symbols');
  await File.fromUri(outputUri).writeAsString(_render(bindings));

  print(' - Writing ${exportsUri.pathSegments.last}');
  await File.fromUri(exportsUri).writeAsString(_renderWindowsExports(symbols));
  print('Done');
}

_MethodBinding? _extractBinding(String source, String symbol) {
  final methodPattern = RegExp(
    '^  (?<returnType>[^\\n]+?) $symbol\\(',
    multiLine: true,
  );
  final match = methodPattern.firstMatch(source);
  if (match == null) {
    return null;
  }

  final signatureStart = match.start;
  final openParamsIndex = source.indexOf('(', signatureStart);
  final closeParamsIndex = _findMatchingDelimiter(
    source,
    openParamsIndex,
    openDelimiter: '(',
    closeDelimiter: ')',
  );
  final params = source.substring(openParamsIndex + 1, closeParamsIndex);

  final bodyStart = source.indexOf('{', closeParamsIndex);
  if (bodyStart == -1) {
    throw StateError('Unable to find method body for $symbol');
  }
  final bodyEnd = source.indexOf('\n  }', bodyStart);
  if (bodyEnd == -1) {
    throw StateError('Unable to find end of method body for $symbol');
  }

  final delegateCall = '_$symbol(';
  final argsStart = source.indexOf(delegateCall, bodyStart);
  if (argsStart == -1 || argsStart > bodyEnd) {
    throw StateError('Unable to find delegated call for $symbol');
  }
  final openArgsIndex = argsStart + delegateCall.length - 1;
  final closeArgsIndex = _findMatchingDelimiter(
    source,
    openArgsIndex,
    openDelimiter: '(',
    closeDelimiter: ')',
  );
  final args = source.substring(openArgsIndex + 1, closeArgsIndex).trim();

  final lookupMarker = 'late final _${symbol}Ptr =';
  final ptrIndex = source.indexOf(lookupMarker, bodyEnd);
  if (ptrIndex == -1) {
    throw StateError('Unable to find native lookup block for $symbol');
  }
  final lookupStart = source.indexOf('_lookup<', ptrIndex);
  if (lookupStart == -1) {
    throw StateError('Unable to find _lookup<...> block for $symbol');
  }
  final typeStart = lookupStart + '_lookup<'.length;
  final typeEnd = _findMatchingDelimiter(
    source,
    typeStart - 1,
    openDelimiter: '<',
    closeDelimiter: '>',
  );
  final nativeType = _unwrapNativeFunction(
    source.substring(typeStart, typeEnd).trim(),
    symbol,
  );

  return _MethodBinding(
    name: symbol,
    returnType: match.namedGroup('returnType')!.trim(),
    params: params,
    args: args,
    nativeType: nativeType,
  );
}

String _unwrapNativeFunction(String nativeType, String symbol) {
  const prefix = 'ffi.NativeFunction<';
  if (!nativeType.startsWith(prefix) || !nativeType.endsWith('>')) {
    throw StateError('Unexpected native lookup type for $symbol: $nativeType');
  }
  return nativeType.substring(prefix.length, nativeType.length - 1).trim();
}

int _findMatchingDelimiter(
  String source,
  int openIndex, {
  required String openDelimiter,
  required String closeDelimiter,
}) {
  var depth = 0;
  for (var i = openIndex; i < source.length; i++) {
    final char = source[i];
    if (char == openDelimiter) {
      depth++;
    } else if (char == closeDelimiter) {
      depth--;
      if (depth == 0) {
        return i;
      }
    }
  }
  throw StateError(
    'Unable to find matching closing delimiter for $openDelimiter at $openIndex',
  );
}

String _render(List<_MethodBinding> bindings) {
  final out = <String>[
    '// Copyright 2026 Google LLC',
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
    '// AUTO GENERATED FILE, DO NOT EDIT.',
    '//',
    '// Generated by `tool/generate_direct_bindings.dart`.',
    '// ignore_for_file: constant_identifier_names',
    '// ignore_for_file: non_constant_identifier_names',
    '// ignore_for_file: type=lint',
    '',
    "import 'dart:ffi' as ffi;",
    '',
    "import '../../third_party/boringssl/generated_bindings.dart';",
    '',
    "const _assetId = '$_assetId';",
    '',
    'class WebcryptoBoringSsl {',
    '  const WebcryptoBoringSsl();',
    '',
  ];

  for (final binding in bindings) {
    out.addAll([
      '  ${binding.returnType} ${binding.name}(${binding.params}) {',
      '    return _native_${binding.name}(${binding.args});',
      '  }',
      '',
      '  @ffi.Native<${binding.nativeType}>(',
      "    symbol: 'webcrypto_${binding.name}',",
      '    assetId: _assetId,',
      '  )',
      '  external static ${binding.returnType} _native_${binding.name}(',
      binding.params,
      '  );',
      '',
    ]);
  }

  out.add('}');
  out.add('');
  return out.join('\n');
}

String _renderWindowsExports(List<String> symbols) {
  final out = <String>[
    '; AUTO GENERATED FILE, DO NOT EDIT.',
    '; Generated by `tool/generate_direct_bindings.dart`.',
    'EXPORTS',
    ..._helperExports,
    ...symbols.map((symbol) => 'webcrypto_$symbol'),
    '',
  ];
  return out.join('\n');
}
