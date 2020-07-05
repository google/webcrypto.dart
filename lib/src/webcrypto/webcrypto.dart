library webcrypto;

// TODO: Split this file into parts

import 'package:meta/meta.dart';
import 'dart:async';
import 'dart:typed_data';
import '../impl_stub.dart'
    if (dart.library.ffi) '../impl_ffi/impl_ffi.dart'
    if (dart.library.js) '../impl_js/impl_js.dart' as impl;

part 'webcrypto.aescbc.dart';
part 'webcrypto.aesctr.dart';
part 'webcrypto.aesgcm.dart';
part 'webcrypto.digest.dart';
part 'webcrypto.ecdh.dart';
part 'webcrypto.ecdsa.dart';
part 'webcrypto.hkdf.dart';
part 'webcrypto.hmac.dart';
part 'webcrypto.pbkdf2.dart';
part 'webcrypto.random.dart';
part 'webcrypto.rsaoaep.dart';
part 'webcrypto.rsapss.dart';
part 'webcrypto.rsassapkcs1v15.dart';

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
