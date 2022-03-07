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

import 'dart:ffi';
import 'dart:io' show Platform;

import 'symbols.generated.dart';
import '../bindings/generated_bindings.dart';
import 'utils.dart';

/// Dynamically load `webcrypto_lookup_symbol` function.
final Pointer<T> Function<T extends NativeType>(String symbolName) lookup = () {
  var library = Platform.isAndroid || Platform.isLinux
      ? DynamicLibrary.open('libwebcrypto.so')
      : DynamicLibrary.executable();

  try {
    // Try to lookup the 'webcrypto_lookup_symbol' symbol.
    final webcryptoDartDL = WebCryptoDartDL(library);
    final webcrypto_lookup_symbol = webcryptoDartDL.webcrypto_lookup_symbol;

    // Return a function from Sym to lookup using `webcrypto_lookup_symbol`
    final lookup = <T extends NativeType>(String s) =>
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
