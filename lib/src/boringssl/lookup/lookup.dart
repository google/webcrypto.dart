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

const _nativeAssetId = 'package:webcrypto/webcrypto.dart';

typedef _VoidLookup = Pointer<Void> Function(String symbolName);

bool _nativeAssetsAvailable = true;

@Native<Pointer<Void> Function(Int32)>(
  symbol: 'webcrypto_lookup_symbol',
  assetId: _nativeAssetId,
)
external Pointer<Void> _nativeWebcryptoLookupSymbol(int index);

/// Resolve a lookup function either from native assets or fall back to dynamic
/// libraries built by the legacy setup flow.
final Pointer<T> Function<T extends NativeType>(String symbolName) lookup =
    _resolveLookup();

Pointer<T> Function<T extends NativeType>(String symbolName) _resolveLookup() {
  final nativeLookup = _createNativeAssetLookup();
  _VoidLookup? legacyLookup;

  _VoidLookup ensureLegacy() => legacyLookup ??= _createLegacyLookup();

  if (nativeLookup != null) {
    return <T extends NativeType>(String symbolName) {
      if (_nativeAssetsAvailable) {
        try {
          return nativeLookup(symbolName).cast<T>();
        } on Object {
          _nativeAssetsAvailable = false;
        }
      }
      final fallback = ensureLegacy();
      return fallback(symbolName).cast<T>();
    };
  }

  _nativeAssetsAvailable = false;
  final fallback = ensureLegacy();
  return <T extends NativeType>(String symbolName) =>
      fallback(symbolName).cast<T>();
}

_VoidLookup? _createNativeAssetLookup() {
  if (!_shouldAttemptNativeAssets()) {
    return null;
  }

  try {
    _nativeWebcryptoLookupSymbol(Sym.BN_bin2bn.index);
  } on Object {
    return null;
  }

  return (String symbolName) {
    final sym = symFromString(symbolName);
    return _nativeWebcryptoLookupSymbol(sym.index);
  };
}

_VoidLookup _createLegacyLookup() {
  try {
    late DynamicLibrary library;
    if (Platform.isAndroid || Platform.isLinux) {
      library = DynamicLibrary.open('libwebcrypto.so');
    } else if (Platform.isWindows) {
      library = DynamicLibrary.open('webcrypto.dll');
    } else {
      library = DynamicLibrary.executable();
      if (!library.providesSymbol('webcrypto_lookup_symbol')) {
        final toolLookup = lookupLibraryInDotDartTool();
        if (toolLookup != null) {
          return (String symbolName) => toolLookup<Void>(symbolName);
        }
        throw UnsupportedError(
          'package:webcrypto could not find required symbols in executable. '
          'If you are using package:webcrypto from scripts or `flutter test` '
          'make sure to run `flutter pub run webcrypto:setup` in the current '
          'root project.',
        );
      }
    }

    final webcrypto = WebCrypto(library);
    final webcryptoLookup = webcrypto.webcrypto_lookup_symbol;

    return (String symbolName) =>
        webcryptoLookup(symFromString(symbolName).index);
  } on ArgumentError {
    final toolLookup = lookupLibraryInDotDartTool();
    if (toolLookup != null) {
      return (String symbolName) => toolLookup<Void>(symbolName);
    }

    throw UnsupportedError(
      'package:webcrypto cannot be used from scripts or `flutter test` '
      'unless `flutter pub run webcrypto:setup` has been run for the current '
      'root project.',
    );
  }
}

bool _shouldAttemptNativeAssets() =>
    Platform.isLinux || Platform.isMacOS || Platform.isWindows;

final Pointer<T> Function<T extends NativeType>(String symbolName)
_cachedLookup = lookup;

/// Gives access to BoringSSL symbols.
final BoringSsl ssl = BoringSsl.fromLookup(_cachedLookup);

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
