import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:webcrypto/webcrypto.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  const requiredTagLengths = <int>[96, 104, 112, 120, 128];
  const providerDependentTagLengths = <int>[32, 64];

  testWidgets('public API AES-128-GCM encryption matches known vector', (
    _,
  ) async {
    final key = await AesGcmSecretKey.importRawKey(
      base64Decode('3nle6RpFx77jwrksoNUb1Q=='),
    );
    final ciphertext = await key.encryptBytes(
      base64Decode(
        'dWx0cmljZXMKcG9zdWVyZSBjdWJpbGlhIEN1cmFlOyBBbGlxdWFtIHF1aXMgaGVu'
        'ZHJlcml0IGxhY3VzLgo=',
      ),
      base64Decode('AAEECRAZJDFAUWR5kKnE4Q=='),
    );

    expect(
      base64Encode(ciphertext),
      '4FNVScf36O/F5uUwqA7qSKbDAhCDHaxdvYZmpViAbEY2GE2kYS18TFRVhfbY82T2'
      'JHfqOhIuMStKtHPOkmaB3pThaKK84ARXFj0xIL0b',
    );
  });

  testWidgets('public API AES-GCM supports required tag lengths', (_) async {
    final key = await AesGcmSecretKey.importRawKey(
      base64Decode('uIfV8fgL3cR69VFEZBwFVKZYAEWRGl3k6JlT6mGAd1o='),
    );
    final iv = base64Decode('AAEECRAZJDFAUWR5kKnE4Q==');
    final additionalData = base64Decode(
      'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=',
    );
    final plaintext = base64Decode(
      'bnNlY3RldHVyCmFsaXF1ZXQsIGRvbG9yIGF1Z3VlIG1vbGVzdGk=',
    );

    for (final tagLength in requiredTagLengths) {
      final ciphertext = await key.encryptBytes(
        plaintext,
        iv,
        additionalData: additionalData,
        tagLength: tagLength,
      );
      expect(
        ciphertext,
        hasLength(plaintext.length + tagLength ~/ 8),
        reason: 'tagLength=$tagLength',
      );
      expect(
        await key.decryptBytes(
          ciphertext,
          iv,
          additionalData: additionalData,
          tagLength: tagLength,
        ),
        plaintext,
        reason: 'tagLength=$tagLength',
      );
    }
  });

  testWidgets('public API AES-GCM reports provider-dependent short tags', (
    _,
  ) async {
    final key = await AesGcmSecretKey.importRawKey(
      base64Decode('uIfV8fgL3cR69VFEZBwFVKZYAEWRGl3k6JlT6mGAd1o='),
    );
    final iv = base64Decode('AAEECRAZJDFAUWR5kKnE4Q==');
    final additionalData = base64Decode(
      'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=',
    );
    final plaintext = base64Decode(
      'bnNlY3RldHVyCmFsaXF1ZXQsIGRvbG9yIGF1Z3VlIG1vbGVzdGk=',
    );

    for (final tagLength in providerDependentTagLengths) {
      try {
        final ciphertext = await key.encryptBytes(
          plaintext,
          iv,
          additionalData: additionalData,
          tagLength: tagLength,
        );
        expect(
          await key.decryptBytes(
            ciphertext,
            iv,
            additionalData: additionalData,
            tagLength: tagLength,
          ),
          plaintext,
          reason: 'tagLength=$tagLength',
        );
      } on UnsupportedError catch (e) {
        expect(
          e.message,
          contains('tagLength=$tagLength'),
          reason: 'tagLength=$tagLength',
        );
      }
    }
  });
}
