import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:webcrypto/webcrypto.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('public API HKDF-SHA-256 matches RFC 5869', (_) async {
    final key = await HkdfSecretKey.importRawKey(
      Uint8List(22)..fillRange(0, 22, 0x0b),
    );
    final derived = await key.deriveBits(
      42 * 8,
      Hash.sha256,
      Uint8List.fromList(List<int>.generate(13, (i) => i)),
      Uint8List.fromList(List<int>.generate(10, (i) => 0xf0 + i)),
    );

    expect(
      base64Encode(derived),
      'PLJfJfqs1XqQQ09k0DYvKi0tCpDPGlpMXbAtVuzExb80AHII1biHGFhl',
    );
  });
}
