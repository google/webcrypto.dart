// Imports the Flutter Driver API.
import 'package:flutter_driver/flutter_driver.dart';
import 'package:test/test.dart';

void main() {
  group('Webcrypto Example App', () {
    final keyOutputFinder = find.byValueKey('KeyOutput');
    final importKeyButtonFinder = find.byValueKey('ImportRawKey');
    final genKeyOutputFinder = find.byValueKey('GenKeyOutput');
    final generateKeyButtonFinder = find.byValueKey('GenerateKey');

    FlutterDriver driver;

    // Connect to the Flutter driver before running any tests.
    setUpAll(() async {
      driver = await FlutterDriver.connect();
    });

    // Close the connection to the driver after the tests have completed.
    tearDownAll(() async {
      if (driver != null) {
        driver.close();
      }
    });

    test('no imported key', () async {
      // Verify that no key has been imported in the begining.
      expect(await driver.getText(keyOutputFinder), "-");
    });

    test('import raw aes key', () async {
      // Tap the button to import the key.
      await driver.tap(importKeyButtonFinder);

      // The outout should contain the importet key now.
      expect(await driver.getText(keyOutputFinder),
          matches('.*"3nle6RpFx77jwrksoNUb1Q".*'));
    });

    test('no aes key generated', () async {
      // Verify that no key has been generated in the begining.
      expect(await driver.getText(genKeyOutputFinder), "-");
    });

    test('generate aes cbc key', () async {
      // Tap the button to import the key.
      await driver.tap(generateKeyButtonFinder);

      // The outout should contain the importet key now.
      expect(await driver.getText(genKeyOutputFinder),
          matches('.*"alg":"A256CBC".*'));
    });
  });
}
