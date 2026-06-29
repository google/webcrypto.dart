import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:webcrypto/webcrypto.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('public API HMAC-SHA-256 signature matches known vector', (
    _,
  ) async {
    final key = await HmacSecretKey.importRawKey(
      List<int>.filled(20, 0x0b),
      Hash.sha256,
    );
    final signature = await key.signBytes(utf8.encode('Hi There'));

    expect(
      base64Encode(signature),
      'sDRMYdjbOFNcqK/OrwvxK4gdwgDJgz2nJuk3bC4yz/c=',
    );
  });
}
