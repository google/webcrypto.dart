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
import 'dart:typed_data';

import 'package:webcrypto/src/impl_ffi/impl_ffi.dart' as ffi_impl;
import 'package:webcrypto/src/impl_jni/impl_jni.dart' as jni_impl;

import '../test/src/jni_test_setup_io.dart';

const _configurations = [
  (iterations: 1000, samples: 11),
  (iterations: 10000, samples: 11),
  (iterations: 100000, samples: 7),
];

Future<void> main() async {
  final setupError = jniHelperSetupSkipReason;
  if (setupError != null) {
    throw StateError(setupError);
  }
  spawnJniForDesktopTests();

  final password = Uint8List.fromList([0, 1, 2, 0x80, 0xff]);
  final salt = Uint8List.fromList([0xff, 0x80, 2, 1, 0]);
  final jniKey = await jni_impl.webCryptImpl.pbkdf2SecretKey.importRawKey(
    password,
  );
  final ffiKey = await ffi_impl.webCryptImpl.pbkdf2SecretKey.importRawKey(
    password,
  );

  stdout.writeln('backend,iterations,samples,median_ms');
  for (final configuration in _configurations) {
    final iterations = configuration.iterations;
    final expected = await ffiKey.deriveBits(
      256,
      ffi_impl.webCryptImpl.sha256,
      salt,
      iterations,
    );
    final actual = await jniKey.deriveBits(
      256,
      jni_impl.webCryptImpl.sha256,
      salt,
      iterations,
    );
    if (!_bytesEqual(actual, expected)) {
      throw StateError('JNI and FFI results differ at $iterations iterations');
    }

    final ffiMedian = await _medianMilliseconds(() async {
      await ffiKey.deriveBits(
        256,
        ffi_impl.webCryptImpl.sha256,
        salt,
        iterations,
      );
    }, samples: configuration.samples);
    final jniMedian = await _medianMilliseconds(() async {
      await jniKey.deriveBits(
        256,
        jni_impl.webCryptImpl.sha256,
        salt,
        iterations,
      );
    }, samples: configuration.samples);

    stdout.writeln(
      'ffi,$iterations,${configuration.samples},'
      '${ffiMedian.toStringAsFixed(2)}',
    );
    stdout.writeln(
      'jni,$iterations,${configuration.samples},'
      '${jniMedian.toStringAsFixed(2)}',
    );
  }
}

Future<double> _medianMilliseconds(
  Future<void> Function() operation, {
  required int samples,
}) async {
  for (var i = 0; i < 2; i++) {
    await operation();
  }

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

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) {
    return false;
  }
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}
