@TestOn('linux')

import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:webcrypto/src/webcrypto_extension/webcrypto_extension.dart'
    as ext;

void main() async {
  group('compare', () {
    test('compare (equal)', () {
      final A = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      final B = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      expect(ext.compare(A, B), isTrue);
    });

    test('compare (not equal)', () {
      final A = Uint8List.fromList([42, 2, 3, 4, 5, 6, 7, 8]);
      final B = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      expect(ext.compare(A, B), isFalse);
    });

    test('compare (length not equal)', () {
      final A = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      final B = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7]);
      expect(ext.compare(A, B), isFalse);
    });
  });
}
