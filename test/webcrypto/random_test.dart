import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';
import '../utils.dart';

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
