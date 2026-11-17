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

@TestOn('browser')
library;

import 'dart:convert';

import 'package:convert/convert.dart';
import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';

void main() {
  late final List<dynamic> vectors;

  setUpAll(() async {
    final channel = spawnHybridUri('chromium_vector_loader.dart');
    channel.sink.add('bad_ec_keys');
    final source = await channel.stream.first as String;
    await channel.sink.close();

    final json = source
        .split('\n')
        .where((line) => !line.trimLeft().startsWith('//'))
        .join('\n');
    vectors = jsonDecode(json) as List<dynamic>;
    expect(vectors, hasLength(21));
  });

  // https://github.com/google/webcrypto.dart/issues/459
  const firefoxSkipReasons = <int, String>{
    14: 'Private scalar does not match the public coordinates',
    16: 'P-384 public point is not on the curve',
    17: 'P-256 private scalar equals the curve order',
    19: 'P-521 private scalar exceeds the curve order by 11',
  };

  for (var index = 0; index < 21; index++) {
    test(
      'Chromium bad EC key vector $index',
      () async {
        final vector = vectors[index] as Map<String, dynamic>;
        final curve = switch (vector['crv']) {
          'P-256' => EllipticCurve.p256,
          'P-384' => EllipticCurve.p384,
          'P-521' => EllipticCurve.p521,
          final name => throw FormatException('Unsupported curve: $name'),
        };
        final format = vector['key_format'] as String;
        final key = vector['key'] as Object;
        final isPrivateKey =
            format == 'pkcs8' ||
            (format == 'jwk' && (key as Map<String, dynamic>).containsKey('d'));
        final Future<Object> imported = switch (format) {
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
          'spki' => EcdsaPublicKey.importSpkiKey(
            hex.decode(key as String),
            curve,
          ),
          _ => throw StateError('Unsupported key format: $format'),
        };
        await expectLater(
          imported,
          throwsA(isA<FormatException>()),
          reason: 'Chromium vector $index: ${vector['error']}',
        );
      },
      onPlatform: firefoxSkipReasons.containsKey(index)
          ? {'firefox': Skip(firefoxSkipReasons[index]!)}
          : null,
    );
  }
}
