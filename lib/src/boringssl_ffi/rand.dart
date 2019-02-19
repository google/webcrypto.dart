import 'dart:ffi';
import 'types.dart';
import 'helpers.dart';

// See:
// https://commondatastorage.googleapis.com/chromium-boringssl-docs/rand.h.html

/// RAND_bytes writes len bytes of random data to buf and returns one.
///
/// ```c
/// int RAND_bytes(uint8_t *buf, size_t len);
/// ```
final RAND_bytes = lookup('RAND_bytes')
    .lookupFunc<Int32 Function(Bytes, IntPtr)>()
    .asFunction<int Function(Bytes, int)>();
