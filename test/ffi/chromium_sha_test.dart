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

@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:isolate';

import 'package:convert/convert.dart';
import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';

const _testVectorPath = 'third_party/chromium/sha.json';

void main() {
  final vectors = _loadTestVectors();

  group('Chromium SHA vectors', () {
    for (final (index, vector) in vectors.indexed) {
      test('${vector.algorithmName} input length ${vector.input.length} '
          '(vector $index)', () async {
        expect(await vector.algorithm.digestBytes(vector.input), vector.output);
        expect(
          await vector.algorithm.digestStream(
            Stream.fromIterable([
              vector.input.take(1).toList(),
              vector.input.skip(1).toList(),
            ]),
          ),
          vector.output,
        );
      });
    }
  });
}

List<_ShaVector> _loadTestVectors() {
  final packageUri = Isolate.resolvePackageUriSync(
    Uri.parse('package:webcrypto/webcrypto.dart'),
  );
  if (packageUri == null) {
    throw StateError('Unable to locate package:webcrypto.');
  }
  final file = File.fromUri(packageUri.resolve('../$_testVectorPath'));
  if (!file.existsSync()) {
    throw StateError(
      'Missing $_testVectorPath. Run ./tool/update-chromium-test-vectors.sh '
      'to restore vendored vectors.',
    );
  }

  final json = file
      .readAsLinesSync()
      .where((line) => !line.trimLeft().startsWith('//'))
      .join('\n');
  final values = jsonDecode(json) as List<dynamic>;
  return [
    for (final value in values)
      _ShaVector.fromJson(value as Map<String, dynamic>),
  ];
}

final class _ShaVector {
  final String algorithmName;
  final Hash algorithm;
  final List<int> input;
  final List<int> output;

  const _ShaVector({
    required this.algorithmName,
    required this.algorithm,
    required this.input,
    required this.output,
  });

  factory _ShaVector.fromJson(Map<String, dynamic> json) {
    return _ShaVector(
      algorithmName: json['algorithm'] as String,
      algorithm: switch (json['algorithm']) {
        'sha-1' => Hash.sha1,
        'sha-256' => Hash.sha256,
        'sha-384' => Hash.sha384,
        'sha-512' => Hash.sha512,
        final value => throw FormatException('Unsupported hash: $value'),
      },
      input: hex.decode(json['input'] as String),
      output: hex.decode(json['output'] as String),
    );
  }
}
