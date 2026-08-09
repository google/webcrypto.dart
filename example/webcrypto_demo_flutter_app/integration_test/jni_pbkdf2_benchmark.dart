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

import 'dart:typed_data';

import 'package:flutter/foundation.dart' show debugPrint;
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:webcrypto/webcrypto.dart';

const _configurations = [
  (iterations: 1000, samples: 5),
  (iterations: 10000, samples: 5),
  (iterations: 100000, samples: 5),
];

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('benchmarks realistic PBKDF2 iteration counts', (_) async {
    final password = Uint8List.fromList([0, 1, 2, 0x80, 0xff]);
    final salt = Uint8List.fromList([0xff, 0x80, 2, 1, 0]);
    final key = await Pbkdf2SecretKey.importRawKey(password);

    debugPrint('backend,iterations,samples,median_ms');
    for (final configuration in _configurations) {
      final iterations = configuration.iterations;
      final derived = await key.deriveBits(256, Hash.sha256, salt, iterations);
      expect(derived, hasLength(32));

      final median = await _medianMilliseconds(() async {
        await key.deriveBits(256, Hash.sha256, salt, iterations);
      }, samples: configuration.samples);
      debugPrint(
        'jni,$iterations,${configuration.samples},'
        '${median.toStringAsFixed(2)}',
      );
    }
  });
}

Future<double> _medianMilliseconds(
  Future<void> Function() operation, {
  required int samples,
}) async {
  await operation();

  final durations = <int>[];
  for (var i = 0; i < samples; i++) {
    final stopwatch = Stopwatch()..start();
    await operation();
    stopwatch.stop();
    durations.add(stopwatch.elapsedMicroseconds);
  }
  durations.sort();
  return durations[durations.length ~/ 2] / 1000;
}
