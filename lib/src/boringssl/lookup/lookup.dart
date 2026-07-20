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

import 'dart:io' show Platform;

import 'symbols.generated.dart';
import 'utils.dart';

export 'symbols.generated.dart' show Sym;

// The URI of this Dart library is also the Native Assets identity registered by
// hook/build.dart. @Native resolves through NativeAssetsManifest before trying
// an embedder resolver or the current process.
@Native<Pointer<Void> Function(Int32)>(
  symbol: 'webcrypto_lookup_symbol',
  isLeaf: true,
)
external Pointer<Void> _nativeWebcryptoLookupSymbol(int index);

/// Load `webcrypto_lookup_symbol`, preferring the package's Native Asset.
final Pointer<T> Function<T extends NativeType>(String symbolName) lookup = () {
  try {
    // Probe resolution now so a missing manifest enters the compatibility path
    // here rather than failing later on an unrelated crypto operation.
    if (_nativeWebcryptoLookupSymbol(Sym.BN_bin2bn.index) == nullptr) {
      throw StateError('webcrypto_lookup_symbol returned a null pointer.');
    }
    Pointer<T> nativeAssetLookup<T extends NativeType>(String symbol) =>
        _nativeWebcryptoLookupSymbol(symFromString(symbol).index).cast<T>();
    return nativeAssetLookup;
  } on ArgumentError {
    // Continue into the custom-embedder and legacy setup fallbacks below.
  }

  final fallback =
      lookupLibraryBesideExecutable() ?? lookupLibraryInDotDartTool();
  if (fallback != null) return fallback;

  throw UnsupportedError(
    'package:webcrypto could not load its native library on '
    '${Platform.operatingSystem}. Native Assets did not resolve '
    'package:webcrypto/src/boringssl/lookup/lookup.dart and no bundled or '
    '.dart_tool/webcrypto library was found. Rebuild with a Dart/Flutter SDK '
    'that supports package build hooks, or run `dart run webcrypto:setup` for '
    'a legacy direct-script workflow.',
  );
}();

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
