import 'dart:async';
import 'dart:convert' show json;
import 'package:flutter/widgets.dart';
import 'package:flutter/material.dart';
import 'package:flutter_driver/driver_extension.dart';
import '../../test/run_all_tests.dart';

void main() {
  final testNames = <String>[];
  final testCallbacks = <FutureOr<void> Function()>[];

  runAllTests(test: (name, callback) {
    testNames.add(name);
    testCallbacks.add(callback);
  });

  enableFlutterDriverExtension(handler: (String data) async {
    final request = json.decode(data) as Map<String, dynamic>;
    final response = <String, dynamic>{};
    final command = request['command'] as String;

    if (command == 'list-tests') {
      response['tests'] = testNames;
    }
    if (command == 'run-test') {
      final fn = testCallbacks[request['index']];
      String error;
      final logLines = [];
      await runZonedGuarded(fn, (e, st) {
        error ??= e.toString();
        logLines.add('Uncaught error in test: $e\nStackTrace: $st');
      }, zoneSpecification: ZoneSpecification(print: (
        self,
        parent,
        zone,
        line,
      ) {
        logLines.add(line);
      }));
      response['error'] = error;
      response['logLines'] = logLines;
    }

    return json.encode(response);
  });

  runApp(MaterialApp(home: Text('Running webcrypto tests')));
}
