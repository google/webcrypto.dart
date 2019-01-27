@TestOn('browser || linux')

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';

Stream<List<int>> asStream(String data) async* {
  yield Uint8List.fromList(utf8.encode(data));
}

// stringToSign in all samples
final String stringToSign = 'signed-string-data';

// Samples and secretKey for samples
final String secretKey = 'secret-key';
final Map<HashAlgorithm, String> samples = {
  HashAlgorithm.sha1: 'LkW+HO/n18DoOHN0XaNj2rCRIP4=',
  HashAlgorithm.sha256: 'he289xbdo7jy1xF/9gT2BXOfFmiQQFExx1N/x0nHUlk=',
  HashAlgorithm.sha384: 'SD4RvkKmkRpZsYjLsQe7hjlZwn3NPGw1ZVEdamfjBjpmLfkZBTHPaS'
      '/h7BFRPu0b',
  HashAlgorithm.sha512: 'NZZ9+K2eknm/ukrBgrN5Smo+7VuG6qmZC32YlBYxGrcONvdcj/fhmc'
      'oW+/GFbJVrdSAQIeCOBjROZ6ayLxEC1Q==',
};

/// Secret key for length 28 samples
final length28SecretKey = Uint8List.fromList([0xff, 0xff, 0xff, 0xff]);
final Map<HashAlgorithm, String> length28Samples = {
  HashAlgorithm.sha1: 'hcPvVaFlmxXuliFgvE8a9Goignk=',
  HashAlgorithm.sha256: 'ZiFsXCxjDhGBuRdef90WSbaZfdzN7G7Btd4fQIkXfXM=',
  HashAlgorithm.sha384: 'bdQAxQkfRHTUQIItEiQZyQLTLpjDB0/F64t7F2YIdZc+/GiBqblXKf'
      'eaVvp7wFuL',
  HashAlgorithm.sha512: 'ST9Rk5OvwyIICTKzHztqk8E7r1KhgNLmShsNoHk3pZAtxPH9vSzgdb'
      'HRBsult0oqmkds2+ahjj+QT8pqrVJH0Q==',
};

/// Secret key for length 30 samples
final length30SecretKey = Uint8List.fromList([0xaa, 0xaa, 0xaa, 0xaa]);
final Map<HashAlgorithm, String> length30Samples = {
  HashAlgorithm.sha1: 'NzknVDDOZol2hzRSXgqXUiqwxsA=',
  HashAlgorithm.sha256: 'oPsaiXiMqrDpelHXFKGs9DW9h9627a0VWpqBTwqMrGE=',
  HashAlgorithm.sha384: 'HhNmMgafv8rTW1uHpRB67NTZsHpbEbcwz6JN3qhZfnO1EvdMgZynfT'
      'As0b0JLQNb',
  HashAlgorithm.sha512: '9JKS6RbJ91AJoUKKEsk2cTYW+wktbcoFwDFcM787EzQNnIeoBc3q+G'
      'b9n8kStqhqEpGzyKsOQmi9HUuMb5PvGQ==',
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

      test('generateKey', () async {
        final k = await HmacSecretKey.generateKey(
          hash: hash,
          usages: [KeyUsage.sign, KeyUsage.verify],
          extractable: false,
        );
        final sig = await k.sign(data: asStream(stringToSign));
        final ret = await k.verify(
          signature: sig,
          data: asStream(stringToSign),
        );
        expect(ret, isTrue);
        final ret2 = await k.verify(
          signature: sig,
          data: asStream(stringToSign + 'other-string'),
        );
        expect(ret2, isFalse);
      });

      test('importKey (length: 28)', () async {
        // You can only use this to slice the last bits off the key
        final k = await HmacSecretKey.importRawKey(
          keyData: length28SecretKey,
          extractable: true,
          usages: [KeyUsage.sign, KeyUsage.verify],
          hash: hash,
          length: 28,
        );
        final result = await k.verify(
          signature: base64.decode(length28Samples[hash]),
          data: asStream(stringToSign),
        );
        expect(result, isTrue);
      });

      test('importKey (length: 30)', () async {
        // You can only use this to slice the last bits off the key
        final k = await HmacSecretKey.importRawKey(
          keyData: length30SecretKey,
          extractable: true,
          usages: [KeyUsage.sign, KeyUsage.verify],
          hash: hash,
          length: 30,
        );
        final result = await k.verify(
          signature: base64.decode(length30Samples[hash]),
          data: asStream(stringToSign),
        );
        expect(result, isTrue);
      });
    });
  }
}
