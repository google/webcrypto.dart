@TestOn('browser')

import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';

Stream<List<int>> asStream(String data) async* {
  yield Uint8List.fromList(utf8.encode(data));
}

final String stringToSign = 'signed-string-data';
final String secretKey = 'secret-key';

final Map<HashAlgorithm, String> samples = {
  HashAlgorithm.sha1: 'LkW+HO/n18DoOHN0XaNj2rCRIP4=',
  // HashAlgorithm.sha256: 'he289xbdo7jy1xF/9gT2BXOfFmiQQFExx1N/x0nHUlk=',
  // HashAlgorithm.sha384: 'SD4RvkKmkRpZsYjLsQe7hjlZwn3NPGw1ZVEdamfjBjpmLfkZBTHPaS'
  //     '/h7BFRPu0b',
  // HashAlgorithm.sha512: 'NZZ9+K2eknm/ukrBgrN5Smo+7VuG6qmZC32YlBYxGrcONvdcj/fhmc'
  //     'oW+/GFbJVrdSAQIeCOBjROZ6ayLxEC1Q==',
};

void main() {
  for (final hash in HashAlgorithm.values) {
    // If we don't have a sample for the given algorithm we skip it
    if (!samples.containsKey(hash)) {
      continue;
    }

    group('with hash: $hash', () {
      HmacSecretKey key;
      test('importKey', () async {
        key = await HmacSecretKey.importRawKey(
          keyData: Uint8List.fromList(utf8.encode(secretKey)),
          extractable: true,
          usages: [KeyUsage.sign, KeyUsage.verify],
          hash: hash,
        );
      });

      List<int> sig;
      test('sign', () async {
        sig = await key.sign(data: asStream(stringToSign));

        // Compare to the expected result
        expect(base64Encode(sig), equals(samples[hash]));
      });

      // Test that verify works in the positive case
      test('verify (positive)', () async {
        final valid = await key.verify(
          signature: sig,
          data: asStream(stringToSign),
        );
        expect(valid, isTrue);
      });

      // Test that verify works in the negative case
      test('verify (negative)', () async {
        final invalid = await key.verify(
          signature: sig,
          data: asStream('wrong-string'),
        );
        expect(invalid, isFalse);
      });

      test('export', () async {
        final rawKey = await key.exportRawKey();
        expect(utf8.decode(rawKey), equals(secretKey));
      });
    });
  }
}
