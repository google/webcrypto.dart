@TestOn('browser')

import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';

Stream<List<int>> asStream(String data) async* {
  yield Uint8List.fromList(utf8.encode(data));
}

void main() {
  // Test hash algorithms against correct value for 'hello-world', obtained with
  // echo -n 'hello-world' | sha1sum - | cut -d ' ' -f 1 | xxd -r -p | base64
  group('"hello-world"', () {
    test('SHA-1', () async {
      final bytes = await digest(
        hash: HashAlgorithm.sha1,
        data: asStream("hello-world"),
      );
      final hash = base64Encode(bytes);
      expect(hash, equals('+7lpEX7fqRa4bftn/RHezx4zbfA='));
    });

    test('SHA-256', () async {
      final bytes = await digest(
        hash: HashAlgorithm.sha256,
        data: asStream("hello-world"),
      );
      final hash = base64Encode(bytes);
      expect(hash, equals('r6J7RNQ7Aqn+pB0TztwuQBbPz4fF2/mQ5ZNmmqjOKG0='));
    });

    test('SHA-384', () async {
      final bytes = await digest(
        hash: HashAlgorithm.sha384,
        data: asStream("hello-world"),
      );
      final hash = base64Encode(bytes);
      expect(
          hash,
          equals('UT6f7WCFp32YJnp1is4l/ZYnOeQKpE8xjmdkLOwZ3nIP+tmT2aMRFQGJomjVf'
              '5cE'));
    });

    test('SHA-512', () async {
      final bytes = await digest(
        hash: HashAlgorithm.sha512,
        data: asStream("hello-world"),
      );
      final hash = base64Encode(bytes);
      expect(
          hash,
          equals('au78KRIqOWLJDvg09sqtADO//NYpQbemIFppXMOeJ2fbd3inrXbRc6CDueFLI'
              'Q3AISkj9IGyhceEqx/jQNf/TQ=='));
    });
  });
}
