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

import 'package:boring/bindings.dart' as ssl;

import 'utils.dart';

Future<T> checkErrorStack<T>(FutureOr<T> Function() fn) async {
  // Always clear the error stack
  ssl.ERR_clear_error();

  // Operations must consume BoringSSL errors right after each failing call
  // (see _checkOp in lib/src/impl_ffi/impl_ffi.utils.dart), so fail the test
  // if any are left behind.
  final ret = await fn();
  // Formats the first error (if any) and always clears the error stack.
  final err = ssl.extractBoringSslError();
  if (err != null) {
    check(false, err);
  }
  return ret;
}
