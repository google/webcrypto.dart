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

export 'src/webcrypto/webcrypto.dart';
