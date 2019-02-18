import 'dart:ffi';

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
