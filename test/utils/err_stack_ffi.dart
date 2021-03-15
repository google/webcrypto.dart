// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:async';
import 'dart:convert';
import 'dart:ffi' as ffi;

import 'package:ffi/ffi.dart' as ffi;
import 'package:webcrypto/src/boringssl/lookup/lookup.dart' show ssl;

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
        return ret;
      }
      const N = 4096; // Max error message size
      final p = ffi.calloc<ffi.Int8>(N);
      try {
        ssl.ERR_error_string_n(err, p, N);
        final data = p.cast<ffi.Uint8>().asTypedList(N);

        // Take everything until '\0'
        check(false, utf8.decode(data.takeWhile((i) => i != 0).toList()));
      } finally {
        ffi.calloc.free(p);
      }
    } finally {
      ssl.ERR_clear_error();
    }
  }
  return ret;
}
