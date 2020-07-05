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
/// https://commondatastorage.googleapis.com/chromium-boringssl-docs/hmac.h.html
library hmac;

import 'dart:ffi';
import 'types.dart';
import 'lookup/lookup.dart';

/// HMAC_CTX_new allocates and initialises a new HMAC_CTX and returns it, or
/// NULL on allocation failure. The caller must use HMAC_CTX_free to release
/// the resulting object.
///
/// ```c
/// HMAC_CTX *HMAC_CTX_new(void);
/// ```
final HMAC_CTX_new = resolve(Sym.HMAC_CTX_new)
    .lookupFunc<Pointer<HMAC_CTX> Function()>()
    .asFunction<Pointer<HMAC_CTX> Function()>();

/// HMAC_CTX_free calls HMAC_CTX_cleanup and then frees ctx itself.
/// ```c
/// void HMAC_CTX_free(HMAC_CTX *ctx);
/// ```
final HMAC_CTX_free = resolve(Sym.HMAC_CTX_free)
    .lookupFunc<Void Function(Pointer<HMAC_CTX>)>()
    .asFunction<void Function(Pointer<HMAC_CTX>)>();

/// HMAC_Init_ex sets up an initialised HMAC_CTX to use md as the hash function
/// and key as the key. For a non-initial call, md may be NULL, in which case
/// the previous hash function will be used. If the hash function has not
/// changed and key is NULL, ctx reuses the previous key. It returns one on
/// success or zero on allocation failure.
///
/// WARNING: NULL and empty keys are ambiguous on non-initial calls. Passing
/// NULL key but repeating the previous md reuses the previous key rather than
/// the empty key.
///
/// ```c
/// int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, size_t key_len,
///                                 const EVP_MD *md, ENGINE *impl);
/// ```
final HMAC_Init_ex = resolve(Sym.HMAC_Init_ex)
    .lookupFunc<
        Uint32 Function(
      Pointer<HMAC_CTX>,
      Pointer<Data>,
      IntPtr,
      Pointer<EVP_MD>,
      Pointer<ENGINE>,
    )>()
    .asFunction<
        int Function(
      Pointer<HMAC_CTX>,
      Pointer<Data>,
      int,
      Pointer<EVP_MD>,
      Pointer<ENGINE>,
    )>();

/// HMAC_Update hashes data_len bytes from data into the current HMAC operation in ctx. It returns one.
/// ```c
/// int HMAC_Update(HMAC_CTX *ctx, const uint8_t *data,
///                                size_t data_len);
/// ```
final HMAC_Update = resolve(Sym.HMAC_Update)
    .lookupFunc<Uint32 Function(Pointer<HMAC_CTX>, Pointer<Bytes>, IntPtr)>()
    .asFunction<int Function(Pointer<HMAC_CTX>, Pointer<Bytes>, int)>();

/// HMAC_Final completes the HMAC operation in ctx and writes the result to out
/// and the sets *out_len to the length of the result. On entry, out must
/// contain at least HMAC_size bytes of space. An output size of EVP_MAX_MD_SIZE
/// will always be large enough. It returns one on success or zero on allocation
/// failure.
///
/// ```c
/// int HMAC_Final(HMAC_CTX *ctx, uint8_t *out,
///                               unsigned int *out_len);
/// ```
final HMAC_Final = resolve(Sym.HMAC_Final)
    .lookupFunc<
        Uint32 Function(
      Pointer<HMAC_CTX>,
      Pointer<Bytes>,
      Pointer<Uint32>,
    )>()
    .asFunction<
        int Function(
      Pointer<HMAC_CTX>,
      Pointer<Bytes>,
      Pointer<Uint32>,
    )>();

/// HMAC_size returns the size, in bytes, of the HMAC that will be produced by
/// ctx. On entry, ctx must have been setup with HMAC_Init_ex.
///
/// ```c
/// size_t HMAC_size(const HMAC_CTX *ctx);
/// ```
final HMAC_size = resolve(Sym.HMAC_size)
    .lookupFunc<IntPtr Function(Pointer<HMAC_CTX>)>()
    .asFunction<int Function(Pointer<HMAC_CTX>)>();
