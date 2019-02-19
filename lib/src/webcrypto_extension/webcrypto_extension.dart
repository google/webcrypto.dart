/// This library exports stubs for the native functions exposed from
/// `libwebcrypto_extension.so`.
///
/// To simplify the native functions we employ the following calling
/// conventions:
///  * Input arguments **must** not be `null`.
///  * Data is always converted to [Uint8List].
///  * The return value is always `dynamic`, if a [String] is returned it is the
///    message for an [OperationException] to be thrown.
library webcrypto_extension;

import 'dart:typed_data';
import '../../webcrypto.dart' show HashAlgorithm, OperationException;
import 'dart-ext:webcrypto_extension';

// The simplest way to call native code: top-level functions.
int systemRand() native "SystemRand";

//---------------------- Utilities

/// Constant-time comparison on [a] and [b].
///
/// Returns `true` if equal, `false` if not, otherwise returns a [String]
/// message for the [OperationException] to be thrown.
dynamic compare(Uint8List a, Uint8List b) native "compare";

//---------------------- Random Bytes

/// Fills [data] with random values.
///
/// Returns `null` if successful, otherwise this returns a [String] message
/// for the [OperationException] to be thrown.
dynamic getRandomValues(Uint8List data) native "getRandomValues";

//---------------------- Hash Algorithms

/// Convert [hash] to integer identifier for [hash] as used in [digest_create].
int hashAlgorithmToHashIdentifier(HashAlgorithm hash) {
  ArgumentError.checkNotNull(hash, 'hash');

  switch (hash) {
    case HashAlgorithm.sha1:
      return 0;
    case HashAlgorithm.sha256:
      return 1;
    case HashAlgorithm.sha384:
      return 2;
    case HashAlgorithm.sha512:
      return 3;
  }
  // This is an invariant we want to check in production.
  throw AssertionError(
    'HashAlgorithm value with index: ${hash.index} is unknown',
  );
}

/// Create a _digest context_ using hash algorithm given by [hashIdentifier].
///
/// Returns an [int] identifying the context if successful, otherwise returns
/// a [String] message for the [OperationException] to be thrown.
dynamic digest_create(int hashIdentifer) native "digest_create";

/// Write [data] to the _digest context_ given by [ctx].
///
/// Returns `null` if successful, otherwise returns
/// a [String] message for the [OperationException] to be thrown.
dynamic digest_write(int ctx, Uint8List data) native "digest_write";

/// Get the hash result from [ctx].
///
/// Returns `Uint8List` if successful, otherwise returns
/// a [String] message for the [OperationException] to be thrown.
dynamic digest_result(int ctx) native "digest_result";

/// Release all resources by the _digest context_.
///
/// This should be called in a `finally` block following [digest_create].
/// This may not be called more than once, or with values not aquired by
/// [digest_create].
///
/// Returns `null` if successful, otherwise returns
/// a [String] message for the [OperationException] to be thrown.
dynamic digest_destroy(int ctx) native "digest_destroy";

//---------------------- HMAC

/// See documentation for `digest_*` methods, other that [hmac_create] taking
/// [keyData] these are very similar.
///
/// Signature: (int hashIdentifier, Uint8List keyData) -> int | String
dynamic hmac_create(int hashIdentifier, Uint8List keyData) native "hmac_create";

/// Signature: (int ctx, Uint8List data) -> Null | String
dynamic hmac_write(int ctx, Uint8List data) native "hmac_write";

/// Signature: (int ctx) -> Uint8List | String
dynamic hmac_result(int ctx) native "hmac_result";

/// Signature: (int ctx) -> Null | String
dynamic hmac_destroy(int ctx) native "hmac_destroy";

//---------------------- RSASSA_PKCS1_v1_5

/// Import public key in 'spki' format and associated it with the given
/// [keyHandle].
///
/// The [keyHandle] is an object that the external memory will be associated
/// with. Memory will be released when the [keyHandle] is garbage collected.
///
/// Signature: (keyhandle, keyData) -> Null | String
dynamic rsassa_importSpkiKey(Object keyHandle, Uint8List keyData)
    native "rsassa_importSpkiKey";

/// See documentation for `digest_*` methods, other that [rsassa_verify_create]
/// taking [keyhandle] these are very similar.
///
/// Signature: (int hashIdentifier, Uint8List keyData) -> int | String
dynamic rsassa_verify_create(int hashIdentifier, Object keyHandle)
    native "rsassa_verify_create";

/// Signature: (int ctx, Uint8List data) -> Null | String
dynamic rsassa_verify_write(int ctx, Uint8List data)
    native "rsassa_verify_write";

/// Signature: (int ctx) -> Uint8List | String
dynamic rsassa_verify_result(int ctx) native "rsassa_verify_result";

/// Signature: (int ctx) -> Null | String
dynamic rsassa_verify_destroy(int ctx) native "rsassa_verify_destroy";
