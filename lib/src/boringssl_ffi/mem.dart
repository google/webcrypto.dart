import 'dart:ffi';
import 'types.dart';
import 'helpers.dart';

/// CRYPTO_memcmp returns zero iff the len bytes at a and b are equal. It takes
/// an amount of time dependent on len, but independent of the contents of
/// a and b. Unlike memcmp, it cannot be used to put elements into a defined
/// order as the return value when a != b is undefined, other than to be
/// non-zero.
///
/// ```c
/// int CRYPTO_memcmp(const void *a, const void *b, size_t len);
/// ```
final CRYPTO_memcmp = lookup('CRYPTO_memcmp')
    .lookupFunc<Uint32 Function(Data, Data, IntPtr)>()
    .asFunction<int Function(Data, Data, int)>();
