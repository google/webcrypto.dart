import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:webcrypto/webcrypto.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

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
}
