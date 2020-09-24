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

import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';
import '../utils/utils.dart';

void isAllZero(TypedData data) {
  data.buffer.asUint8List().forEach((b) => check(b == 0));
}

void isNotAllZero(TypedData data) {
  check(data.buffer.asUint8List().any((b) => b != 0));
}

void main() => runTests();

/// Run all tests, exported for use in `../run_all_tests.dart`.
void runTests({TestFn test = test}) {
  test('fillRandomBytes: Uint8List', () {
    final data = Uint8List(16 * 1024);
    isAllZero(data);
    fillRandomBytes(data);
    isNotAllZero(data);
  });

  test('fillRandomBytes: Uint16List', () {
    final data = Uint16List(4 * 1024);
    isAllZero(data);
    fillRandomBytes(data);
    isNotAllZero(data);
  });

  test('fillRandomBytes: Uint32List', () {
    final data = Uint32List(2 * 1024);
    isAllZero(data);
    fillRandomBytes(data);
    isNotAllZero(data);
  });

  test('fillRandomBytes: Int8List', () {
    final data = Int8List(16 * 1024);
    isAllZero(data);
    fillRandomBytes(data);
    isNotAllZero(data);
  });

  test('fillRandomBytes: Int16List', () {
    final data = Int16List(4 * 1024);
    isAllZero(data);
    fillRandomBytes(data);
    isNotAllZero(data);
  });

  test('fillRandomBytes: Int32List', () {
    final data = Int32List(2 * 1024);
    isAllZero(data);
    fillRandomBytes(data);
    isNotAllZero(data);
  });

  test('fillRandomBytes: Maximum buffer', () {
    final data = Uint8List(64 * 1024);
    isAllZero(data);
    fillRandomBytes(data);
    isNotAllZero(data);
  });
}
