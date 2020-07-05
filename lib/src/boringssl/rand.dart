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
/// https://commondatastorage.googleapis.com/chromium-boringssl-docs/rand.h.html
library rand;

import 'dart:ffi';
import 'types.dart';
import 'lookup/lookup.dart';

/// RAND_bytes writes len bytes of random data to buf and returns one.
///
/// ```c
/// int RAND_bytes(uint8_t *buf, size_t len);
/// ```
final RAND_bytes = resolve(Sym.RAND_bytes)
    .lookupFunc<Int32 Function(Pointer<Bytes>, IntPtr)>()
    .asFunction<int Function(Pointer<Bytes>, int)>();
