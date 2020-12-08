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

import 'dart:async';
import 'dart:typed_data';
import 'dart:convert';
import 'package:webcrypto/webcrypto.dart';
import 'package:test/test.dart' as t;

/// Log [value] from tests.
void log(Object value) => print(value);

/// True, if data should be dumped, this is mostly generated test case
const _dumpData = bool.fromEnvironment('webcrypto.dump', defaultValue: false);
//const _dumpData = true; // manual override

/// Dump data, if enabled with `dart -D webcrypto.dump=true <file>`.
///
/// This can also be overwritten by manually tweaking the [_dumpData] variable.
void dump(Map data) {
  if (_dumpData) {
    final json =
        JsonEncoder.withIndent('  ').convert(data).replaceAll('\n', '\n| ');
    log('| $json');
  }
}

/// Check if [condition] hold.
void check(bool condition, [String message = 'check failed']) {
  if (!condition) {
    t.fail(message);
  }
}

/// Test function compatible with `package:test/test.dart`.
typedef TestFn = void Function(String name, FutureOr<void> Function() fn);

/// Compare if two byte arrays are equal.
bool equalBytes(List<int> a, List<int> b) => base64Encode(a) == base64Encode(b);

/// Convert [Stream<List<int>>] to [Uint8List].
Future<Uint8List> bufferStream(Stream<List<int>> data) async {
  ArgumentError.checkNotNull(data, 'data');
  final result = <int>[];
  // TODO: Make this allocation stuff smarter
  await for (var chunk in data) {
    result.addAll(chunk);
  }
  return Uint8List.fromList(result);
}

Hash hashFromJson(dynamic json) {
  if (json is Map) {
    json = json['hash'];
  }
  if (json == 'sha-1') {
    return Hash.sha1;
  }
  if (json == 'sha-256') {
    return Hash.sha256;
  }
  if (json == 'sha-384') {
    return Hash.sha384;
  }
  if (json == 'sha-512') {
    return Hash.sha512;
  }
  throw AssertionError('invalid hash specification');
}

String hashToJson(Hash h) {
  if (h == Hash.sha1) {
    return 'sha-1';
  }
  if (h == Hash.sha256) {
    return 'sha-256';
  }
  if (h == Hash.sha384) {
    return 'sha-384';
  }
  if (h == Hash.sha512) {
    return 'sha-512';
  }
  throw AssertionError('invalid hash implementation');
}

String curveToJson(EllipticCurve curve) {
  if (curve == EllipticCurve.p256) {
    return 'p-256';
  }
  if (curve == EllipticCurve.p384) {
    return 'p-384';
  }
  if (curve == EllipticCurve.p521) {
    return 'p-521';
  }
  throw AssertionError('invalid curve implementation');
}

EllipticCurve curveFromJson(dynamic json) {
  if (json is Map) {
    json = json['curve'];
  }
  if (json == 'p-256') {
    return EllipticCurve.p256;
  }
  if (json == 'p-384') {
    return EllipticCurve.p384;
  }
  if (json == 'p-521') {
    return EllipticCurve.p521;
  }
  throw AssertionError('invalid curve specification');
}

List<int>? bytesFromJson(Map<String, dynamic> json, String key) {
  if (json[key] != null) {
    return base64Decode(json[key]);
  }
  return null;
}

String? bytesToJson(List<int>? bytes) {
  if (bytes != null) {
    return base64Encode(bytes);
  }
  return null;
}

/// Flip the first bit of every byte
///
/// Useful for generating an invalidate signature.
Uint8List flipFirstBits(List<int> data) =>
    Uint8List.fromList(data.map((i) => i ^ 0x1).toList());
