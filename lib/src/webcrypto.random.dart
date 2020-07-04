part of webcrypto;

/// Fill [destination] with cryptographically random values.
///
/// Does not accept a [destination] larger than `65536` bytes, use multiple
/// calls to obtain more random bytes.
///
/// **Example**
/// ```dart
/// import 'dart:convert' show base64;
/// import 'dart:typed_data' show Uint8List;
/// import 'package:webcrypto/webcrypto.dart';
///
/// // Allocated a byte array of 64 bytes.
/// final bytes = Uint8List(64);
///
/// // Fill with random bytes.
/// fillRandomBytes(bytes);
///
/// // Print base64 encoded random bytes.
/// print(base64.encode(bytes));
/// ```
void fillRandomBytes(
  TypedData destination,
  // Note: Uint8List and friends all implement TypedData, but dartdoc has a bug
  //       where it's not reporting this.
) {
  ArgumentError.checkNotNull(destination, 'destination');
  // This limitation is given in the Web Cryptography Specification, see:
  // https://www.w3.org/TR/WebCryptoAPI/#Crypto-method-getRandomValues
  if (destination.lengthInBytes > 65536) {
    throw ArgumentError.value(destination, 'destination',
        'array of more than 65536 bytes is not allowed');
  }

  impl.fillRandomBytes(destination);
}
