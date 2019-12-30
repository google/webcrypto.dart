import 'dart:ffi';
import 'types.dart';
import 'helpers.dart';

/// BoringSSL has its own set of allocation functions, which keep track of
/// allocation lengths and zero them out before freeing. All memory returned by
/// BoringSSL API calls must therefore generally be freed using OPENSSL_free
/// unless stated otherwise.

/// OPENSSL_malloc acts like a regular malloc.
///
/// ```c
/// OPENSSL_EXPORT void *OPENSSL_malloc(size_t size);
/// ```
final OPENSSL_malloc = lookup('OPENSSL_malloc')
    .lookupFunc<Pointer<Data> Function(IntPtr)>()
    .asFunction<Pointer<Data> Function(int)>();

/// OPENSSL_free does nothing if ptr is NULL. Otherwise it zeros out the memory
/// allocated at ptr and frees it.
///
/// ```c
/// OPENSSL_EXPORT void OPENSSL_free(void *ptr);
/// ```
final OPENSSL_free = lookup('OPENSSL_free')
    .lookupFunc<Void Function(Pointer<Data>)>()
    .asFunction<void Function(Pointer<Data>)>();

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
    .lookupFunc<Uint32 Function(Pointer<Data>, Pointer<Data>, IntPtr)>()
    .asFunction<int Function(Pointer<Data>, Pointer<Data>, int)>();

/// OPENSSL_memdup returns an allocated, duplicate of size bytes from data or
/// NULL on allocation failure.
///
/// ```c
/// OPENSSL_EXPORT void *OPENSSL_memdup(const void *data, size_t size);
/// ```
final OPENSSL_memdup = lookup('OPENSSL_memdup')
    .lookupFunc<Pointer<Data> Function(Pointer<Data>, IntPtr)>()
    .asFunction<Pointer<Data> Function(Pointer<Data>, int)>();
