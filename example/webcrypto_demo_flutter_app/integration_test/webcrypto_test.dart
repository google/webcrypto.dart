import 'package:flutter_test/flutter_test.dart';
import 'package:flutter/material.dart';
import 'package:integration_test/integration_test.dart';

import 'package:webcrypto_example/main.dart' as app;
import 'package:webcrypto/src/testing/testing.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('package:webcrypto tests', () {
    runAllTests(test);
  });

  group('webcrypto_example test', () {
    testWidgets('app can compute a hash', (tester) async {
      app.main();
      await tester.pumpAndSettle();

      expect(find.textContaining('2aae6c35c94'), findsNothing);

      final input = find.byType(TextField);
      await tester.enterText(input, 'hello world');

      final refresh = find.byTooltip('compute hash');
      await tester.tap(refresh);

      await tester.pumpAndSettle();

      expect(find.textContaining('2aae6c35c94'), findsOneWidget);
    });
  });
}
