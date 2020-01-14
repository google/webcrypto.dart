import 'dart:async';
import 'dart:convert';
import 'dart:ffi' as ffi;

import 'package:ffi/ffi.dart' as ffi;
import 'package:webcrypto/src/boringssl/boringssl.dart' as ssl;

import 'utils.dart';

Future<T> checkErrorStack<T>(FutureOr<T> Function() fn) async {
  // Always clear the error stack
  ssl.ERR_clear_error();

  // TODO: Do this in every finally{} instead and use _Scope to do it.
  //       Then have an assert that there is no errors.
  //       That way we clear errors in production and fail on them in testing.
  final ret = await fn();
  if (ssl.ERR_peek_error() != 0) {
    try {
      // Get the error.
      final err = ssl.ERR_get_error();
      if (err == 0) {
        return null;
      }
      const N = 4096; // Max error message size
      final p = ffi.allocate<ssl.Bytes>(count: N);
      try {
        ssl.ERR_error_string_n(err, p, N);
        final data = p.cast<ffi.Uint8>().asTypedList(N);

        // Take everything until '\0'
        check(false, utf8.decode(data.takeWhile((i) => i != 0).toList()));
      } finally {
        ffi.free(p);
      }
    } finally {
      ssl.ERR_clear_error();
    }
  }
  return ret;
}
