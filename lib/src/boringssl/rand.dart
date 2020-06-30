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
