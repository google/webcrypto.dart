import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:webcrypto/src/impl_jni/impl_jni.dart' as jni_impl;
import 'package:webcrypto/webcrypto.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('JCA digest works through the public API', (_) async {
    final data = utf8.encode('hello-world');
    final digest = await Hash.sha256.digestBytes(data);
    final jcaDigest = await jni_impl.webCryptImpl.sha256.digestBytes(data);

    expect(digest, jcaDigest);
    expect(
      base64Encode(digest),
      'r6J7RNQ7Aqn+pB0TztwuQBbPz4fF2/mQ5ZNmmqjOKG0=',
    );
  });
}
