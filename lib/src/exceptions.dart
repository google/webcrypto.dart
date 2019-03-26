/// Base class for all WebCrypto releated exceptions.
///
/// All _exceptions_ thrown by methods in this package inherets from
/// [WebCryptoException]. In addition methods of this package may
/// also throw the following _errors_:
///  * [ArgumentError] is thrown when a parameter is out of range.
///  * [StateError] is thrown when a type is used in an invalid state, such as
///    an attempt to extract a [CryptoKey] that is not _extractable_, or using
///    a [CryptoKey] for a _usage_ it was not declared to do at creation.
abstract class WebCryptoException implements Exception {
  final String message;
  const WebCryptoException(this.message);

  @override
  String toString() => this.message;
}

/// Thrown when an algorithm or operation isn't supported.
///
/// This is thrown when the underlying implementation doesn't support the
/// algorithm or operation. It is not thrown because the algorithm or operation
/// is being used incorrectly.
///
/// Attempts to extract key that can be extracted results in a [StateError].
/// Providing incorrect invalid parameters results in a [ArgumentError].
class NotSupportedException extends WebCryptoException {
  // Note: We could use UnsupportedError from 'dart:core' instead, but in
  //       webcrypto an unsupported feature is not an error but an exception.
  //       It's possible we change this as few people want to do feature
  //       detection this way, and you technically can catch errors if needed.

  NotSupportedException(String message) : super(message);
}

/// Thrown if input data is invalid.
///
/// This happens if the key being parsed is invalid or the signature being
/// verified doesn't have the correct format.
///
/// This is not thrown in response to invalid arguments, such as a negative
/// exponent in RSA.
class DataException extends WebCryptoException {
  DataException(String message) : super(message);
}

/// Thrown when an operation failed for an operation-specific reason.
class OperationException extends WebCryptoException {
  OperationException(String message) : super(message);
}
