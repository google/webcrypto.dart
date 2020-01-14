import 'dart:async';

Future<T> checkErrorStack<T>(FutureOr<T> Function() fn) async {
  return fn();
}
