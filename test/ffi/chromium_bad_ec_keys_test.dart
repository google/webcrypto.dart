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

import 'package:convert/convert.dart';
import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';

const _testVectorPath = 'third_party/chromium/bad_ec_keys.json';

void main() {
  final vectors = _loadTestVectors();

  group('Chromium bad EC key vectors', () {
    for (final (index, vector) in vectors.indexed) {
      test('${vector.description} (vector $index)', () async {
        await expectLater(
          vector.importKey(),
          throwsA(isA<FormatException>()),
          reason: 'Chromium expectation: ${vector.expectedError}',
        );
      });
    }
  });
}

List<_BadEcKeyVector> _loadTestVectors() {
  final file = File(_testVectorPath);
  if (!file.existsSync()) {
    throw StateError(
      'Missing $_testVectorPath. Run tests from the package root or run '
      './tool/update-chromium-test-vectors.sh to restore vendored vectors.',
    );
  }

  // Chromium's file is JSON with comment-only lines. Keep the vendored file
  // byte-for-byte compatible with upstream and remove comments only when it is
  // loaded by this VM-only test.
  final json = file
      .readAsLinesSync()
      .where((line) => !line.trimLeft().startsWith('//'))
      .join('\n');
  final values = jsonDecode(json) as List<dynamic>;

  return [
    for (final value in values)
      _BadEcKeyVector.fromJson(value as Map<String, dynamic>),
  ];
}

final class _BadEcKeyVector {
  final EllipticCurve curve;
  final String expectedError;
  final String format;
  final Object key;

  const _BadEcKeyVector({
    required this.curve,
    required this.expectedError,
    required this.format,
    required this.key,
  });

  factory _BadEcKeyVector.fromJson(Map<String, dynamic> json) {
    return _BadEcKeyVector(
      curve: switch (json['crv']) {
        'P-256' => EllipticCurve.p256,
        'P-384' => EllipticCurve.p384,
        'P-521' => EllipticCurve.p521,
        final value => throw FormatException('Unsupported curve: $value'),
      },
      expectedError: json['error'] as String,
      format: json['key_format'] as String,
      key: json['key'] as Object,
    );
  }

  bool get isPrivateKey =>
      format == 'pkcs8' ||
      (format == 'jwk' && (key as Map<String, dynamic>).containsKey('d'));

  String get description =>
      '$format ${isPrivateKey ? 'private' : 'public'} key on $curve';

  Future<Object> importKey() {
    return switch (format) {
      'jwk' when isPrivateKey => EcdsaPrivateKey.importJsonWebKey(
        key as Map<String, dynamic>,
        curve,
      ),
      'jwk' => EcdsaPublicKey.importJsonWebKey(
        key as Map<String, dynamic>,
        curve,
      ),
      'pkcs8' => EcdsaPrivateKey.importPkcs8Key(
        hex.decode(key as String),
        curve,
      ),
      'spki' => EcdsaPublicKey.importSpkiKey(hex.decode(key as String), curve),
      final value => throw StateError(
        'Unsupported key format in Chromium vectors: $value',
      ),
    };
  }
}
