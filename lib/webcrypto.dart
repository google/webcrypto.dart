/// Cryptographic primitives for use on Dart VM and Dart in the browser.
///
/// TODO: Finish documentation of a public identifiers, so far the folliwng
/// items have been documented:
///  * [fillRandomBytes]
///  * [Hash]
///  * [HmacSecretKey]
///  * [RsassaPkcs1V15PrivateKey] and [RsassaPkcs1V15PublicKey].
///
/// ## Exceptions
/// This library will throw the following exceptions:
///  * [FormatException], if input data could not be parsed.
///
/// ## Errors
/// This library will throw the following errors:
///  * [ArgumentError], when an parameter is out of range,
///  * [UnsupportedError], when an operation isn't supported,
///  * [OperationError], when an operation fails operation specific reason, this
///    typically when the underlying cryptographic library returns an error.
///
/// ## Mapping Web Crypto Error
///
///  * `SyntaxError` becomes [ArgumentError],
///  * `QuotaExceededError` becomes [ArgumentError],
///  * `NotSupportedError` becomes [UnsupportedError],
///  * `DataError` becomes [FormatException],
///  * `OperationError` becomes [OperationError],
///  * `InvalidAccessError` shouldn't occur, except for ECDH key derivation with
///     mismatching curves where it becomes an [ArgumentError].
///
library webcrypto;

// TODO: Split this file into parts

import 'package:meta/meta.dart';
import 'dart:async';
import 'dart:typed_data';
import 'src/webcrypto_impl_stub.dart'
    if (dart.library.ffi) 'src/webcrypto_impl_ffi.dart'
    if (dart.library.js) 'src/webcrypto_impl_js.dart' as impl;

part 'src/webcrypto.aescbc.dart';
part 'src/webcrypto.aesctr.dart';
part 'src/webcrypto.aesgcm.dart';
part 'src/webcrypto.digest.dart';
part 'src/webcrypto.ecdh.dart';
part 'src/webcrypto.ecdsa.dart';
part 'src/webcrypto.hkdf.dart';
part 'src/webcrypto.hmac.dart';
part 'src/webcrypto.pbkdf2.dart';
part 'src/webcrypto.random.dart';
part 'src/webcrypto.rsaoaep.dart';
part 'src/webcrypto.rsapss.dart';
part 'src/webcrypto.rsassapkcs1v15.dart';

/// Thrown when an operation failed for an operation-specific reason.
@sealed
abstract class OperationError extends Error {
  OperationError._(); // keep the constructor private.
}

/// A key-pair as returned from key generation.
@sealed
abstract class KeyPair<S, T> {
  KeyPair._(); // keep the constructor private.

  /// Private key for [publicKey].
  S get privateKey;

  /// Public key matching [privateKey].
  T get publicKey;
}

/// Elliptic curves supported by ECDSA and ECDH.
///
/// **Remark**, additional values may be added to this enum in the future.
enum EllipticCurve {
  p256,
  p384,
  p521,
}
