import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:webcrypto/webcrypto.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('public API SHA-256 digest matches known vector', (_) async {
    final data = utf8.encode('hello-world');
    final digest = await Hash.sha256.digestBytes(data);

    expect(
      base64Encode(digest),
      'r6J7RNQ7Aqn+pB0TztwuQBbPz4fF2/mQ5ZNmmqjOKG0=',
    );
  });
}
