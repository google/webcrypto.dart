import 'dart:ffi';
import 'dart:typed_data';

/// digest algorithm.
class EVP_MD extends Pointer<Void> {}

/// digest context.
class EVP_MD_CTX extends Pointer<Void> {}

/// HMAC context.
class HMAC_CTX extends Pointer<Void> {}

/// ENGINE, usually just leave this NULL.
class ENGINE extends Pointer<Void> {}

/// An EVP_PKEY object represents a public or private key. A given object may be
/// used concurrently on multiple threads by non-mutating functions, provided no
/// other thread is concurrently calling a mutating function. Unless otherwise
/// documented, functions which take a const pointer are non-mutating and
/// functions which take a non-const pointer are mutating.
class EVP_PKEY extends Pointer<Void> {}

/// EVP_PKEY_CTX objects hold the context of an operation (e.g. signing or
/// encrypting) that uses a public key.
class EVP_PKEY_CTX extends Pointer<Void> {}

/// An RSA object represents a public or private RSA key. A given object may be
/// used concurrently on multiple threads by non-mutating functions, provided no
/// other thread is concurrently calling a mutating function. Unless otherwise
/// documented, functions which take a const pointer are non-mutating and
/// functions which take a non-const pointer are mutating.
class RSA extends Pointer<Void> {}

/// Type for `void*` used to represent opaque data.
class Data extends Pointer<Void> {}

/// Type for `uint8_t*` used to represent byte data.
class Bytes extends Pointer<Uint8> {}

/// Load [data] into a [Pointer] of type [T] and call [fn], and free the pointer
/// when [fn] returns.
///
/// This is an auxiliary function for getting a [Pointer] representation of
/// an [Uint8List] without risk of memory leaks.
R withInputPointer<T extends Pointer, R>(List<int> data, R Function(T) fn) {
  final p = allocate<Uint8>(count: data.length);
  for (int i = 0; i < data.length; i++) {
    p.elementAt(i).store(data[i]);
  }
  try {
    return fn(p.cast<T>());
  } finally {
    p.free();
  }
}

/// Allocated a [size] bytes [Pointer] of type [T] and call [fn], and copy the
/// data from the pointer to an [Uint8List] when [fn] returns. Freeing the
/// pointer when [fn] returns.
///
/// This is an auxiliary function for getting data out of functions that takes
/// an output buffer.
Uint8List withOutputPointer<T extends Pointer>(int size, void Function(T) fn) {
  final p = allocate<Uint8>(count: size);
  try {
    fn(p.cast<T>());
    final result = Uint8List(size);
    for (int i = 0; i < size; i++) {
      result[i] = p.elementAt(i).load<int>();
    }
    return result;
  } finally {
    p.free();
  }
}
