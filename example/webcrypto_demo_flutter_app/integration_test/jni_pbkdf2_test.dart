import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:webcrypto/webcrypto.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('public API PBKDF2-HMAC-SHA-256 matches known vector', (_) async {
    final key = await Pbkdf2SecretKey.importRawKey(utf8.encode('password'));
    final derived = await key.deriveBits(
      256,
      Hash.sha256,
      utf8.encode('salt'),
      2,
    );

    expect(
      base64Encode(derived),
      'rk0Mla9rRtMtCt/5KPBt0CowP47zwlHf1uLYWpVHTEM=',
    );
  });
}
