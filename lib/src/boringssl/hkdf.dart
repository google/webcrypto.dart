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

/// This library maps symbols from:
/// https://commondatastorage.googleapis.com/chromium-boringssl-docs/hkdf.h.html
library hkdf;

import 'dart:ffi';
import 'types.dart';
import 'lookup/lookup.dart';

//---------------------- HKDF.

/// HKDF computes HKDF (as specified by RFC 5869) of initial keying material
/// secret with salt and info using digest, and outputs out_len bytes to
/// out_key. It returns one on success and zero on error.
///
/// HKDF is an Extract-and-Expand algorithm. It does not do any key stretching,
/// and as such, is not suited to be used alone to generate a key from a
/// password.
///
/// ```c
/// OPENSSL_EXPORT int HKDF(uint8_t *out_key, size_t out_len, const EVP_MD *digest,
///                         const uint8_t *secret, size_t secret_len,
///                         const uint8_t *salt, size_t salt_len,
///                         const uint8_t *info, size_t info_len);
/// ```
final HKDF = resolve(Sym.HKDF)
    .lookupFunc<
        Int32 Function(
      Pointer<Bytes>,
      IntPtr,
      Pointer<EVP_MD>,
      Pointer<Bytes>,
      IntPtr,
      Pointer<Bytes>,
      IntPtr,
      Pointer<Bytes>,
      IntPtr,
    )>()
    .asFunction<
        int Function(
      Pointer<Bytes>,
      int,
      Pointer<EVP_MD>,
      Pointer<Bytes>,
      int,
      Pointer<Bytes>,
      int,
      Pointer<Bytes>,
      int,
    )>();

/// From `hkdf.h`
///
/// ```c
/// #define HKDF_R_OUTPUT_TOO_LARGE 100
/// ```
const int HKDF_R_OUTPUT_TOO_LARGE = 100;
