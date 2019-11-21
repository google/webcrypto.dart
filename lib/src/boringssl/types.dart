import 'dart:ffi';

/// digest algorithm.
class EVP_MD extends Struct {}

/// digest context.
class EVP_MD_CTX extends Struct {}

/// HMAC context.
class HMAC_CTX extends Struct {}

/// ENGINE, usually just leave this NULL.
class ENGINE extends Struct {}

/// An EVP_PKEY object represents a public or private key. A given object may be
/// used concurrently on multiple threads by non-mutating functions, provided no
/// other thread is concurrently calling a mutating function. Unless otherwise
/// documented, functions which take a const pointer are non-mutating and
/// functions which take a non-const pointer are mutating.
class EVP_PKEY extends Struct {}

/// EVP_PKEY_CTX objects hold the context of an operation (e.g. signing or
/// encrypting) that uses a public key.
class EVP_PKEY_CTX extends Struct {}

/// Big number.
class BIGNUM extends Struct {}

/// bn_gencb_st, or BN_GENCB, holds a callback function that is used by
/// generation functions that can take a very long time to complete.
/// Use BN_GENCB_set to initialise a BN_GENCB structure.
class BN_GENCB extends Struct {}

/// An RSA object represents a public or private RSA key. A given object may be
/// used concurrently on multiple threads by non-mutating functions, provided no
/// other thread is concurrently calling a mutating function. Unless otherwise
/// documented, functions which take a const pointer are non-mutating and
/// functions which take a non-const pointer are mutating.
class RSA extends Struct {}

/// Type for `void*` used to represent opaque data.
class Data extends Struct {}

/// Type for `uint8_t*` used to represent byte data.
class Bytes extends Struct {}
