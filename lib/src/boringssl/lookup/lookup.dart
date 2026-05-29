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

import 'direct_bindings.generated.dart';

@Native<Size Function()>(
  symbol: 'webcrypto_get_CBB_size',
  assetId: 'package:webcrypto/webcrypto.dart',
)
external int _nativeWebcryptoGetCbbSize();

@Native<Pointer<Void> Function()>(
  symbol: 'webcrypto_get_EVP_PKEY_free_address',
  assetId: 'package:webcrypto/webcrypto.dart',
)
external Pointer<Void> _nativeWebcryptoGetEvpPkeyFreeAddress();

/// Gives access to BoringSSL symbols exported directly from the bundled asset.
final WebcryptoBoringSsl ssl = const WebcryptoBoringSsl();

/// Gets the native `sizeof(CBB)` value from the bundled helper library.
int nativeWebcryptoGetCbbSize() => _nativeWebcryptoGetCbbSize();

/// Gets the native address of `EVP_PKEY_free` for [NativeFinalizer].
Pointer<NativeFunction<Void Function(Pointer<EVP_PKEY>)>>
nativeEvpPkeyFreeAddress() => _nativeWebcryptoGetEvpPkeyFreeAddress().cast();

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
