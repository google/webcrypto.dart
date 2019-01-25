@TestOn('browser || linux')

import 'dart:typed_data';

import 'package:webcrypto/webcrypto.dart';
import 'package:test/test.dart';

void isAllZero(TypedData data) {
  data.buffer.asUint8List().forEach((b) => expect(b, equals(0)));
}

void isNotAllZero(TypedData data) {
  expect(data.buffer.asUint8List().any((b) => b != 0), isTrue);
}

void main() {
  group('getRandomValues', () {
    test('Uint8List', () {
      final data = Uint8List(16 * 1024);
      isAllZero(data);
      getRandomValues(data);
      isNotAllZero(data);
    });

    test('Uint16List', () {
      final data = Uint16List(4 * 1024);
      isAllZero(data);
      getRandomValues(data);
      isNotAllZero(data);
    });

    test('Uint32List', () {
      final data = Uint32List(2 * 1024);
      isAllZero(data);
      getRandomValues(data);
      isNotAllZero(data);
    });

    test('Int8List', () {
      final data = Int8List(16 * 1024);
      isAllZero(data);
      getRandomValues(data);
      isNotAllZero(data);
    });

    test('Int16List', () {
      final data = Int16List(4 * 1024);
      isAllZero(data);
      getRandomValues(data);
      isNotAllZero(data);
    });

    test('Int32List', () {
      final data = Int32List(2 * 1024);
      isAllZero(data);
      getRandomValues(data);
      isNotAllZero(data);
    });

    test('Maximum buffer', () {
      final data = Uint8List(64 * 1024);
      isAllZero(data);
      getRandomValues(data);
      isNotAllZero(data);
    });

    test('Maximum buffer + 1', () {
      final data = Uint8List(64 * 1024 + 1);
      isAllZero(data);
      expect(() {
        getRandomValues(data);
      }, throwsArgumentError);
    });
  });
}
