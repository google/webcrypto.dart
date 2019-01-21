import 'dart:typed_data';

import 'package:webcrypto/webcrypto.dart';
import 'package:test/test.dart';

void main() {
  group('getRandomValues', () {
    test('Uint8List', () {
      final data = Uint8List(16 * 1024);
      data.forEach((b) => expect(b, equals(0)));
      getRandomValues(data);
      expect(data, contains(1));
      expect(data, contains(2));
      expect(data, contains(0));
    });
  });
}
