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

// ignore_for_file: non_constant_identifier_names

import 'dart:ffi';

import '../../third_party/boringssl/generated_bindings.dart';
import '../bindings/generated_bindings.dart';

import 'dart:io' show Platform;

import 'symbols.generated.dart';
import 'utils.dart';

export 'symbols.generated.dart' show Sym;

/// Dynamically load `webcrypto_lookup_symbol` function.
final Pointer<T> Function<T extends NativeType>(String symbolName) lookup = () {
  try {
    final library = Platform.isAndroid || Platform.isLinux
        ? DynamicLibrary.open('libwebcrypto.so')
        : DynamicLibrary.executable();

    // Try to lookup the 'webcrypto_lookup_symbol' symbol.
    final webcryptoDartDL = WebCryptoDartDL(library);
    final webcrypto_lookup_symbol = webcryptoDartDL.webcrypto_lookup_symbol;

    // Return a function from Sym to lookup using `webcrypto_lookup_symbol`
    Pointer<T> lookup<T extends NativeType>(String s) =>
        webcrypto_lookup_symbol(symFromString(s).index).cast<T>();

    // Initialize the dynamic linking with Dart.
    initialize_dart_dl(lookup);

    return lookup;
  } on ArgumentError {
    final lookup = lookupLibraryInDotDartTool();
    if (lookup != null) {
      return lookup;
    }

    throw UnsupportedError(
      'package:webcrypto cannot be used from scripts or `flutter test` '
      'unless `flutter pub run webcrypto:setup` has been run for the current '
      'root project.',
    );
  }
}();

final Pointer<T> Function<T extends NativeType>(String symbolName)
    _cachedLookup = lookup;

/// Gives access to BoringSSL symbols.
final BoringSsl ssl = BoringSsl.fromLookup(_cachedLookup);

/// Gives access to WebCrypto symbols.
final WebCryptoDartDL dl = WebCryptoDartDL.fromLookup(_cachedLookup);

/// ERR_GET_LIB returns the library code for the error. This is one of the
/// ERR_LIB_* values.
///
/// ```c
/// #define ERR_GET_LIB(packed_error) ((int)(((packed_error) >> 24) & 0xff))
/// ```
int ERR_GET_LIB(int packed_error) => (packed_error >> 24) & 0xff;

/// ERR_GET_REASON returns the reason code for the error. This is one of
/// library-specific LIB_R_* values where LIB is the library (see ERR_GET_LIB).
/// Note that reason codes are specific to the library.
///
/// ```c
/// #define ERR_GET_REASON(packed_error) ((int)((packed_error) & 0xfff))
/// ```
int ERR_GET_REASON(int packed_error) => packed_error & 0xfff;
