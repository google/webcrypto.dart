import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:webcrypto/webcrypto.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('public API AES-128-CBC encryption matches known vector', (
    _,
  ) async {
    final key = await AesCbcSecretKey.importRawKey(
      base64Decode('nJ0IrxKwen1VN2/rfLsmmA=='),
    );
    final ciphertext = await key.encryptBytes(
      base64Decode(
        'dmVzdGlidWx1bSBsdWN0dXMgZGlhbSwgcXVpcwppbnRlcmR1bSBsZW8gYWxpcXVh'
        'bSBhYy4gTnVuYyBhYyBtaSBpbiBs',
      ),
      base64Decode('AAEECRAZJDFAUWR5kKnE4Q=='),
    );

    expect(
      base64Encode(ciphertext),
      'MlBdzmsDQSRORkwayz7U9P7v87lgsVRRTrWsZi3qnWiqTW+m6K3KRQ4B1I1u+W7r'
      '/kBCBQt404253SV0DeIHNe/HUesVja7CB5jvJUQ6GmQ=',
    );
  });
}
