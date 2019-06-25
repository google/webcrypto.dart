/// Outline of all classes **including those not implemented yet**.
///
/// ## CHANGELOG
/// Since `draft2.dart`:
///
///  * Return types are `UInt8List` instead of `List<int>`
///  * `TypedData` no longer used for input parameter (uses `List<int>` consistently)
///  * Added a series of `QUESTION:` comments in source code.
///
/// Since initial draft in `webcrypto.dart` and `incomplete.dart`:
///
///  * Removed `CryptoKey` base class.
///  * Removed `KeyUsages` (all keys can be used for all operations).
///  * Removed `extractable` (all keys can be extracted).
///  * Renamed `CryptoKeyPair` to `KeyPair`.
///  * Required parameters are now all positional parameters.
///  * Removed the `HashAlgorithm` enum.
///  * Added the `Hasher` abstract class.
///  * Added constants `sha1`, `sha256`, `sha384`, and, `sha512`.
///
///
/// ## Exceptions
///
/// We throw [NotSupportedException] if an operation is not supported by the
/// platform in question, typically a browser. We throw [FormatException] if
/// input data could not be parsed, typically, failure to parse a key.
///
/// ## Errors
///
/// We throw [ArgumentError] is thrown when a parameter is out of range, and
/// [OperationError] is thrown when an operation fails for an operation-specific
/// reason.
library draft3;

import 'dart:async';
import 'dart:typed_data';

// TODO: Add exportRaw()/importRaw to ECDSA which also supports raw format.

/// Thrown when an algorithm or operation isn't supported.
///
/// This is thrown when the underlying implementation doesn't support the
/// algorithm or operation. It is not thrown because the algorithm or operation
/// is being used incorrectly.
class NotSupportedException implements Exception {
  final String _message;

  // Note: We could use UnsupportedError from 'dart:core' instead, but in
  //       webcrypto an unsupported feature is not an error but an exception.
  //       It's possible we change this as few people want to do feature
  //       detection this way, and you technically can catch errors if needed.

  // QUESTION: Should we use UnsupportedError or UnimplementedError, as few
  //           users will do feature detection anyway. And it's still possible.
  //           This also means we don't clutter documentation.

  NotSupportedException(this._message);

  @override
  String toString() => this._message;
}

/// Thrown when an operation failed for an operation-specific reason.
class OperationError extends Error {
  // QUESTION: Is there a generic error we could throw instead?
  //           This typically happens because the crypto library returns an
  //           error. In the web crypto spec you'll find steps such as:
  //           "3. If performing the operation results in an error, then throw an OperationError."
  //           See also: https://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-Exceptions
  //           (I understand this an internal crypto library errors).

  final String message;
  OperationError._(this.message);
  @override
  String toString() => this.message;
}

/// A key-pair as returned from key generation.
abstract class KeyPair<S, T> {
  KeyPair._(); // keep the constructor private.

  /// Private key for [publicKey].
  S get privateKey;

  /// Public key matching [privateKey].
  T get publicKey;
}

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
/// getRandomValues(bytes.buffer);
///
/// // Print base64 encoded random bytes.
/// print(base64.encode(bytes));
/// ```
void getRandomValues(
  ByteBuffer destination,
  // QUESTION: What type should this be? I don't want to return a buffer.
  //           Filling a buffer should offer better performance.
  // QUESTION: Should we even have this... dart:math does this too, it's just slow.
) {
  ArgumentError.checkNotNull(destination, 'destination');
  // This limitation is given in the Web Cryptography Specification, see:
  // https://www.w3.org/TR/WebCryptoAPI/#Crypto-method-getRandomValues
  if (destination.lengthInBytes > 65536) {
    throw ArgumentError.value(destination, 'destination',
        'array of more than 65536 bytes is not allowed');
  }

  throw UnimplementedError('TODO: Implement this');
}

/// A cryptographic hash algorithm implementation.
///
/// **WARNING:** Custom implementations of this class cannot be passed to
/// to other methods in this library.
abstract class Hasher {
  // QUESTION: Should this be a function typedef instead? Can we do function
  //           identity on all platforms? HmacSecretKey can only accept the
  //           implementations defined in this library. When passing to webcryto
  //           we must pass as a string.
  //           See: https://dart.dev/guides/language/effective-dart/design#avoid-defining-a-one-member-abstract-class-when-a-simple-function-will-do

  /// Compute a cryptographic hash-sum of [data] stream using this [Hasher].
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:io' show File;
  /// import 'dart:convert' show base64;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Pick a file to hash.
  /// String fileToHash = '/etc/passwd';
  ///
  /// // Compute hash of fileToHash with sha-256
  /// List<int> hash = await sha256.digest(
  ///   File(fileToHash).openRead(),
  /// );
  ///
  /// // Print the base64 encoded hash
  /// print(base64.encode(hash));
  /// ```
  ///
  /// This package does not provide a convenient function for hashing a
  /// byte array. But as illustrated in the example below this can be achieved
  /// by wrapping the byte array as a stream.
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show base64, utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Compute hash of 'hello world' with sha-256
  /// List<int> hash = await sha256.digest(
  ///   Stream.fromIterable([
  ///     // In this case our stream contains a single chunk of bytes.
  ///     utf8.encode('hello world'),
  ///   ]),
  /// );
  ///
  /// // Print the base64 encoded hash
  /// print(base64.encode(hash));
  /// ```
  Future<Uint8List> digest(Stream<List<int>> data);
}

/// SHA-1 as specified in [FIPS PUB 180-4][1].
///
/// **This algorithm is considered weak** and should not be used in new
/// cryptographic applications.
///
/// [1]: https://doi.org/10.6028/NIST.FIPS.180-4
const Hasher sha1 = null; // TODO: Implement this

/// SHA-256 as specified in [FIPS PUB 180-4][1].
///
/// [1]: https://doi.org/10.6028/NIST.FIPS.180-4
const Hasher sha256 = null; // TODO: Implement this

/// SHA-384 as specified in [FIPS PUB 180-4][1].
///
/// [1]: https://doi.org/10.6028/NIST.FIPS.180-4
const Hasher sha384 = null; // TODO: Implement this

/// SHA-512 as specified in [FIPS PUB 180-4][1].
///
/// [1]: https://doi.org/10.6028/NIST.FIPS.180-4
const Hasher sha512 = null; // TODO: Implement this

// QUESTION: Should these Hasher implementations be `const` or `final`?
// QUESTION: Should these Hasher implementation be top-level elements or static
//           properties on the `Hasher` class?
//           (is this perhaps easier to find, as they would be namespaced)
//           NOTE: factory constructors might be cool.

/// Key for signing/verifying with HMAC.
///
/// An [HmacSecretKey] instance holds a symmetric secret key and a
/// [Hasher], which can be used to create and verify HMAC signatures as
/// specified in [FIPS PUB 180-4][1].
///
/// Instances of [HmacSecretKey] can be imported using
/// [HmacSecretKey.importRawKey] or generated using [HmacSecretKey.generateKey].
///
/// [1]: https://doi.org/10.6028/NIST.FIPS.180-4
abstract class HmacSecretKey {
  HmacSecretKey._(); // keep the constructor private.

  /// Import [HmacSecretKey] from raw [keyData].
  ///
  /// Creates an [HmacSecretKey] using [keyData] as secret key, and running
  /// HMAC with given [hash] algorithm.
  ///
  /// If given [length] specifies the length of the key, this must be not be
  /// less than number of bits in [keyData] - 7. The [length] only allows
  /// cutting bits of the last byte in [keyData]. In practice this is the same
  /// as zero'ing the last bits in [keyData].
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// final key = await HmacSecretKey.importRawKey(
  ///   utf8.encode('a-secret-key'),  // don't use string in practice
  ///   sha256,
  /// );
  /// ```
  static Future<HmacSecretKey> importRawKey(
    List<int> keyData,
    Hasher hasher, {
    int length,
  }) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(hasher, 'hasher');
    // These limitations are given in Web Cryptography Spec:
    // https://www.w3.org/TR/WebCryptoAPI/#hmac-operations
    if (length != null && length > keyData.length * 8) {
      throw ArgumentError.value(
          length, 'length', 'must be less than number of bits in keyData');
    }
    if (length != null && length <= (keyData.length - 1) * 8) {
      throw ArgumentError.value(
        length,
        'length',
        'must be greater than number of bits in keyData - 8, you can attain '
            'the same effect by removing bytes from keyData',
      );
    }

    throw UnimplementedError('TODO: Implement this');
  }

  /// Import [HmacSecretKey] from [JWK][1].
  ///
  /// TODO: finish implementation and documentation.
  ///
  /// [1]: https://tools.ietf.org/html/rfc7517
  static Future<HmacSecretKey> importJsonWebKey(
    Map<String, Object> jwk,
    Hasher hasher, {
    int length,
  }) {
    ArgumentError.checkNotNull(jwk, 'jwk');
    ArgumentError.checkNotNull(hasher, 'hasher');
    // TODO: Validate length in the native implememtation

    throw UnimplementedError('TODO: Implement this');
  }

  /// Generate random [HmacSecretKey].
  ///
  /// The [length] specifies the length of the secret key in bits. If omitted
  /// the random key will use the same number of bits as the underlying hash
  /// algorithm given in [hasher].
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate a new random HMAC secret key.
  /// final key = await HmacSecretKey.generate(sha256);
  /// ```
  static Future<HmacSecretKey> generateKey(
    Hasher hasher, {
    int length,
  }) {
    ArgumentError.checkNotNull(hasher, 'hasher');
    if (length != null && length <= 0) {
      throw ArgumentError.value(length, 'length', 'must be positive');
    }

    throw UnimplementedError('TODO: Implement this');
  }

  /// Compute an HMAC signature of given [data] stream.
  ///
  /// This computes an HMAC signature of the [data] stream using hash algorithm
  /// and secret key material held by this [HmacSecretKey].
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show base64, utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate an HmacSecretKey.
  /// final key = await HmacSecretKey.generateKey(sha256);
  ///
  /// String stringToSign = 'example-string-to-signed';
  ///
  /// // Compute signature.
  /// final signature = await key.sign(Stream.fromIterable([
  ///   utf8.encode(stringToSign),
  /// ]));
  ///
  /// // Print as base64
  /// print(base64.encode(signature));
  /// ```
  ///
  /// **Warning**, this method should **not** be used for **validating**
  /// other signatures by generating a new signature and then comparing the two.
  /// While this technically works, you application might be vulnerable to
  /// timing attacks. To validate signatures use [verify()], this method
  /// computes a signature and does a fixed-time comparison.
  Future<Uint8List> sign(Stream<List<int>> data);

  /// Verify the HMAC [signature] of given [data] stream.
  ///
  /// This computes an HMAC signature of the [data] stream in the same manner
  /// as [sign()] and conducts a fixed-time comparison against [signature],
  /// returning `true` if the two signatures are equal.
  ///
  /// Notice that it's possible to compute a signature for [data] using
  /// [sign()] and then simply compare the two signatures. This is strongly
  /// discouraged as it is easy to introduce side-channels opening your
  /// application to timing attacks. Use this method to verify signatures.
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show base64, utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate an HmacSecretKey.
  /// final key = await HmacSecretKey.generateKey(sha256);
  ///
  /// String stringToSign = 'example-string-to-signed';
  ///
  /// // Compute signature.
  /// final signature = await key.sign(Stream.fromIterable([
  ///   utf8.encode(stringToSign),
  /// ]));
  ///
  /// // Verify signature.
  /// final result = await key.verify(signature, Stream.fromIterable([
  ///   utf8.encode(stringToSign),
  /// ]));
  /// assert(result == true, 'this signature should be valid');
  /// ```
  Future<bool> verify(List<int> signature, Stream<List<int>> data);

  /// Export [HmacSecretKey] as raw bytes.
  ///
  /// This returns raw bytes making up the secret key. This does not encode the
  /// [Hasher] hash algorithm used.
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate a new random HMAC secret key.
  /// final key = await HmacSecretKey.generate(sha256);
  ///
  /// // Extract the secret key.
  /// final secretBytes = await key.extractRawKey();
  ///
  /// // Print the key as base64
  /// print(base64.encode(secretBytes));
  ///
  /// // If we wanted to we could import the key as follows:
  /// // key = await HmacSecretKey.importRawKey(secretBytes, sha256);
  /// ```
  Future<Uint8List> exportRawKey();

  /// Export [HmacSecretKey] from [JWK][1].
  ///
  /// TODO: finish implementation and documentation.
  ///
  /// [1]: https://tools.ietf.org/html/rfc7517
  Future<Map<String, Object>> exportJsonWebKey();

  // QUESTION: When exporting a key as JWK (JSON Web Key) ww get JSON, should
  //           we return String, Uint8List, or Map<String, Object> ?
  //           Or is this Map<String, dynamic>?
  //           Similarly, we have method that import from JSON Web Keys.
}

/// RSASSA-PKCS1-v1_5 private key for signing messages.
///
/// An [RsassaPkcs1V15PrivateKey] instance hold a private RSA key for computing
/// signatures using the RSASSA-PKCS1-v1_5 scheme as specified in [RFC 3447][1].
///
/// Instances of [RsassaPkcs1V15PrivateKey] can be imported using
/// [RsassaPkcs1V15PrivateKey.importPkcs8Key] or generated using
/// [RsassaPkcs1V15PrivateKey.generateKey] which generates a public-private
/// key-pair.
///
/// [1]: https://tools.ietf.org/html/rfc3447
abstract class RsassaPkcs1V15PrivateKey {
  RsassaPkcs1V15PrivateKey._(); // keep the constructor private.

  /// Import RSASSA-PKCS1-v1_5 private key in PKCS #8 format.
  ///
  /// Creates an [RsassaPkcs1V15PrivateKey] from [keyData] given as the DER
  /// encoding of the _PrivateKeyInfo structure_ specified in [RFC 5208][1].
  /// The hash algorithm to be used is specified by [hasher].
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'package:pem/pem.dart';
  ///
  /// // Read key data from PEM encoded block. This will remove the
  /// // '----BEGIN...' padding, decode base64 and return encoded bytes.
  /// List<int> keyData = PemCodec(PemLabel.privateKey).decode("""
  ///   -----BEGIN PRIVATE KEY-----
  ///   MIGEAgEAMBAGByqG...
  ///   -----END PRIVATE KEY-----
  /// """);
  ///
  /// // Import private key from binary PEM decoded data.
  /// final privateKey = await RsassaPkcs1V15PrivateKey.importPkcs8Key(
  ///   keyData,
  ///   sha256,
  /// );
  ///
  /// // Export the key again (print it in same format as it was given).
  /// List<int> rawKeyData = await privateKey.exportPkcs8Key();
  /// print(PemCodec(PemLabel.privateKey).encode(rawKeyData));
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc5208
  static Future<RsassaPkcs1V15PrivateKey> importPkcs8Key(
    List<int> keyData,
    Hasher hasher,
  ) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(hasher, 'hasher');

    throw UnimplementedError('TODO: Implement this');
  }

  /// Import RSASSA-PKCS1-v1_5 private key in [JWK][1] format.
  ///
  /// TODO: finish implementation and documentation.
  ///
  /// [1]: https://tools.ietf.org/html/rfc7517
  static Future<RsassaPkcs1V15PrivateKey> importJsonWebKey(
    Map<String, Object> jwk,
    Hasher hasher,
  ) {
    ArgumentError.checkNotNull(jwk, 'jwk');
    ArgumentError.checkNotNull(hasher, 'hasher');

    throw UnimplementedError('TODO: Implement this');
  }

  /// Generate an RSASSA-PKCS1-v1_5 public/private key-pair.
  ///
  /// Generate an RSA key with given [modulusLength], this should be at-least
  /// `2048` (though `4096` is often recommended). [publicExponent] should be
  /// `3` or `65537` these are the only values [supported by Chrome][1], unless
  /// you have a good reason to use something else `65537` is recommended.
  ///
  /// The hash algorithm to be used is specified by [hasher].
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'package:pem/pem.dart';
  ///
  /// // Generate a key-pair.
  /// final keyPair = await RsassaPkcs1V15PrivateKey.generateKey(
  ///   4096,
  ///   BigInt.from(65537),
  ///   sha256,
  /// );
  ///
  /// // Export public, so Alice can use it later.
  /// final rawPublicKey = await keyPair.publicKey.exportSpkiKey();
  /// final pemPublicKey = PemCodec(PemLabel.publicKey).encode(rawPublicKey);
  /// print(pemPublicKey); // print key in PEM format: -----BEGIN PUBLIC KEY....
  ///
  /// // Sign a message for Alice.
  /// final message = 'Hi Alice';
  /// final signature = await keyPair.privateKey.sign(
  ///   Stream.fromIterable([utf8.encode(message)]),
  /// );
  ///
  /// // On the other side of the world, Alice has written down the pemPublicKey
  /// // on a trusted piece of paper, but receives the message and signature
  /// // from an untrusted source (thus, desires to verify the signature).
  /// final publicKey = await RsassaPkcs1V15PublicKey.importSpkiKey(
  ///   PemCodec(PemLabel.publicKey).decode(pemPublicKey),
  ///   sha256,
  /// );
  /// final isValid = await publicKey.verify(
  ///   signature,
  ///   Stream.fromIterable([utf8.encode(message)]),
  /// );
  /// if (isValid) {
  ///   print('Authentic message from Bob: $message');
  /// }
  /// ```
  ///
  /// [1]: https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/rsa.cc#286
  static Future<KeyPair<RsassaPkcs1V15PrivateKey, RsassaPkcs1V15PublicKey>>
      generateKey(
    int modulusLength,
    BigInt publicExponent,
    Hasher hasher,
  ) {
    ArgumentError.checkNotNull(modulusLength, 'modulusLength');
    ArgumentError.checkNotNull(publicExponent, 'publicExponent');
    ArgumentError.checkNotNull(hasher, 'hasher');

    throw UnimplementedError('TODO: Implement this');
  }

  /// Sign [data] with this RSASSA-PKCS1-v1_5 private key.
  ///
  /// Returns a signature as a list of raw bytes. This uses the [Hasher]
  /// specified when the key was generated or imported.
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show utf8, base64;
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'package:pem/pem.dart';
  ///
  /// // Read prviate key data from PEM encoded block. This will remove the
  /// // '----BEGIN...' padding, decode base64 and return encoded bytes.
  /// List<int> keyData = PemCodec(PemLabel.privateKey).decode("""
  ///   -----BEGIN PRIVATE KEY-----
  ///   MIGEAgEAMBAGByqG...
  ///   -----END PRIVATE KEY-----
  /// """);
  ///
  /// // Import private key from binary PEM decoded data.
  /// final privatKey = await RsassaPkcs1V15PrivateKey.importPkcs8Key(
  ///   keyData,
  ///   sha256,
  /// );
  ///
  /// // Create a signature for UTF-8 encoded message
  /// final message = 'hello world';
  /// final signature = await privateKey.sign(Stream.fromIterable([
  ///   utf8.encode(message),
  /// ])),
  ///
  /// print('signature: ${base64.encode(signature)}');
  /// ```
  Future<Uint8List> sign(Stream<List<int>> data);

  /// Export this RSASSA-PKCS1-v1_5 private key in PKCS #8 format.
  ///
  /// Returns the DER encoding of the _PrivateKeyInfo structure_ specified in
  /// [RFC 5208][1] as a list of bytes.
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'package:pem/pem.dart';
  ///
  /// // Generate a key-pair.
  /// final keyPair = await RsassaPkcs1V15PrivateKey.generateKey(
  ///   4096,
  ///   BigInt.from(65537),
  ///   sha256,
  /// );
  ///
  /// // Export the private key.
  /// final rawPrivateKey = await keypair.privateKey.exportPkcs8Key();
  ///
  /// // Private keys are often encoded as PEM.
  /// // This encodes the key in base64 and wraps it with:
  /// // '-----BEGIN PRIVATE KEY----'...
  /// print(PemCodec(PemLabel.privateKey).encode(rawPrivateKey));
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc5208
  Future<Uint8List> exportPkcs8Key();

  /// Export RSASSA-PKCS1-v1_5 private key in [JWK][1] format.
  ///
  /// TODO: finish implementation and documentation.
  ///
  /// [1]: https://tools.ietf.org/html/rfc7517
  Future<Map<String, Object>> exportJsonWebKey();
}

/// RSASSA-PKCS1-v1_5 public key for signing messages.
///
/// An [RsassaPkcs1V15PublicKey] instance hold a public RSA key for verification
/// of signatures following the RSASSA-PKCS1-v1_5 scheme as specified
/// in [RFC 3447][1].
///
/// Instances of [RsassaPkcs1V15PublicKey] can be imported using
/// [RsassaPkcs1V15PublicKey.importSpkiKey] or generated using
/// [RsassaPkcs1V15PrivateKey.generateKey] which generates a public-private
/// key-pair.
///
/// [1]: https://tools.ietf.org/html/rfc3447
abstract class RsassaPkcs1V15PublicKey {
  RsassaPkcs1V15PublicKey._(); // keep the constructor private.

  /// Import RSASSA-PKCS1-v1_5 public key in SPKI format.
  ///
  /// Creates an [RsassaPkcs1V15PublicKey] from [keyData] given as the DER
  /// encoding of the _SubjectPublicKeyInfo structure_ specified in
  /// [RFC 5280][1]. The hash algorithm to be used is specified by [hasher].
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'package:pem/pem.dart';
  ///
  /// // Read key data from PEM encoded block. This will remove the
  /// // '----BEGIN...' padding, decode base64 and return encoded bytes.
  /// List<int> keyData = PemCodec(PemLabel.publicKey).decode("""
  ///   -----BEGIN PUBLIC KEY-----
  ///   MIGEAgEAMBAGByqG...
  ///   -----END PUBLIC KEY-----
  /// """);
  ///
  /// // Import public key from binary PEM decoded data.
  /// final publicKey = await RsassaPkcs1V15PublicKey.importSpkiKey(
  ///   keyData,
  ///   sha256,
  /// );
  ///
  /// // Export the key again (print it in same format as it was given).
  /// List<int> rawKeyData = await publicKey.exportSpkiKey();
  /// print(PemCodec(PemLabel.publicKey).encode(rawKeyData));
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc5280
  static Future<RsassaPkcs1V15PublicKey> importSpkiKey(
    List<int> keyData,
    Hasher hasher,
  ) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(hasher, 'hasher');

    throw UnimplementedError('TODO: Implement this');
  }

  /// Import RSASSA-PKCS1-v1_5 public key from [JWK][1].
  ///
  /// TODO: finish implementation and documentation.
  ///
  /// [1]: https://tools.ietf.org/html/rfc7517
  static Future<RsassaPkcs1V15PublicKey> importJsonWebKey(
    Map<String, Object> jwk,
    Hasher hasher,
  ) {
    ArgumentError.checkNotNull(jwk, 'jwk');
    ArgumentError.checkNotNull(hasher, 'hasher');

    throw UnimplementedError('TODO: Implement this');
  }

  /// Verify [signature] of [data] using this RSASSA-PKCS1-v1_5 public key.
  ///
  /// Returns `true` if the signature was made the private key matching this
  /// public key. This uses the [Hasher] specified when the key was
  /// generated or imported.
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate a key-pair.
  /// final keyPair = await RsassaPkcs1V15PrivateKey.generateKey(
  ///   4096,
  ///   BigInt.from(65537),
  ///   sha256,
  /// );
  ///
  /// // Using privateKey Bob can sign a message for Alice.
  /// final message = 'Hi Alice';
  /// final signature = await keyPair.privateKey.sign(Stream.fromIterable([
  ///   utf8.encode(message),
  /// ]));
  ///
  /// // Given publicKey and signature Alice can verify the message from Bob.
  /// final isValid = await keypair.publicKey.verify(
  ///   signature,
  ///   Stream.fromIterable([utf8.encode(message)]),
  /// );
  /// if (isValid) {
  ///   print('Authentic message from Bob: $message');
  /// }
  /// ```
  Future<bool> verify(List<int> signature, Stream<List<int>> data);

  /// Export this RSASSA-PKCS1-v1_5 private key in SPKI format.
  ///
  /// Returns the DER encoding of the _SubjectPublicKeyInfo structure_ specified
  /// in [RFC 5280][1] as a list of bytes. This operation is only allowed if the
  /// key was imported or generated with the [extractable] bit set to `true`.
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'package:pem/pem.dart';
  ///
  /// // Generate a key-pair.
  /// final keyPair = await RsassaPkcs1V15PrivateKey.generateKey(
  ///   4096,
  ///   BigInt.from(65537),
  ///   sha256,
  /// );
  ///
  /// // Export the public key.
  /// final rawPublicKey = await keyPair.publicKey.exportSpkiKey();
  ///
  /// // Public keys are often encoded as PEM.
  /// // This encode the key in base64 and wraps it with:
  /// // '-----BEGIN PUBLIC KEY-----'...
  /// print(PemCodec(PemLabel.publicKey).encode(rawPublicKey));
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc5280
  Future<Uint8List> exportSpkiKey();

  /// Export RSASSA-PKCS1-v1_5 public key in [JWK][1] format.
  ///
  /// TODO: finish implementation and documentation.
  ///
  /// [1]: https://tools.ietf.org/html/rfc7517
  Future<Map<String, Object>> exportJsonWebKey();
}

abstract class RsaPssPrivateKey {
  RsaPssPrivateKey._(); // keep the constructor private.

  static Future<RsaPssPrivateKey> importPkcs8Key(
    List<int> keyData,
    Hasher hasher,
  ) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(hasher, 'hasher');

    throw UnimplementedError('TODO: implement RSA-PSS');
  }

  static Future<RsaPssPrivateKey> importJsonWebKey(
    Map<String, Object> jwk,
    Hasher hasher,
  ) {
    ArgumentError.checkNotNull(jwk, 'jwk');
    ArgumentError.checkNotNull(hasher, 'hasher');

    throw UnimplementedError('TODO: implement RSA-PSS');
  }

  static Future<KeyPair<RsaPssPrivateKey, RsaPssPublicKey>> generateKey(
    int modulusLength,
    BigInt publicExponent,
    Hasher hasher,
  ) {
    ArgumentError.checkNotNull(modulusLength, 'modulusLength');
    ArgumentError.checkNotNull(publicExponent, 'publicExponent');
    ArgumentError.checkNotNull(hasher, 'hasher');

    throw UnimplementedError('TODO: implement RSA-PSS');
  }

  Future<Uint8List> sign(Stream<List<int>> data, int saltLength);

  Future<Uint8List> exportPkcs8Key();

  Future<Map<String, Object>> exportJsonWebKey();
}

abstract class RsaPssPublicKey {
  RsaPssPublicKey._(); // keep the constructor private.

  static Future<RsaPssPublicKey> importSpkiKey(
    List<int> keyData,
    Hasher hasher,
  ) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(hasher, 'hasher');

    throw UnimplementedError('TODO: implement RSA-PSS');
  }

  static Future<RsaPssPublicKey> importJsonWebKey(
    List<int> jwk,
    Hasher hasher,
  ) {
    ArgumentError.checkNotNull(jwk, 'jwk');
    ArgumentError.checkNotNull(hasher, 'hasher');

    throw UnimplementedError('TODO: implement RSA-PSS');
  }

  Future<bool> verify(
    List<int> signature,
    Stream<List<int>> data,
    int saltLength,
  );

  Future<Uint8List> exportSpkiKey();

  Future<Map<String, Object>> exportJsonWebKey();
}

enum EllipticCurve {
  p256,
  p384,
  p521,

  // QUESTION: Should we use objects or strings instead of an enum for forward
  //           compatibility. I suspect it's fair to document that new elements
  //           may be added in the future. Then it's technically not a breaking
  //           change per policy. Besides it's unlikely users will use this.
  //           This is only for passing to ImportKey/generateKey operations!
  //           Any ideas?
}

abstract class EcdsaPrivateKey {
  EcdsaPrivateKey._(); // keep the constructor private.

  static Future<EcdsaPrivateKey> importPkcs8Key(
    List<int> keyData,
    EllipticCurve curve,
  ) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(curve, 'curve');

    throw UnimplementedError('TODO: implement ECDSA');
  }

  static Future<EcdsaPrivateKey> importJsonWebKey(
    List<int> jwk,
    EllipticCurve curve,
  ) {
    ArgumentError.checkNotNull(jwk, 'jwk');
    ArgumentError.checkNotNull(curve, 'curve');

    throw UnimplementedError('TODO: implement ECDSA');
  }

  static Future<KeyPair<EcdsaPrivateKey, EcdsaPublicKey>> generateKey(
    EllipticCurve curve,
  ) {
    ArgumentError.checkNotNull(curve, 'curve');

    throw UnimplementedError('TODO: implement ECDSA');
  }

  Future<Uint8List> sign(Stream<List<int>> data, Hasher hasher);

  Future<Uint8List> exportPkcs8Key();

  Future<Map<String, Object>> exportJsonWebKey();
}

abstract class EcdsaPublicKey {
  EcdsaPublicKey._(); // keep the constructor private.

  static Future<EcdsaPublicKey> importRawKey(
    List<int> keyData,
    EllipticCurve curve,
  ) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(curve, 'curve');

    throw UnimplementedError('TODO: implement ECDSA');
  }

  static Future<EcdsaPublicKey> importSpkiKey(
    List<int> keyData,
    EllipticCurve curve,
  ) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(curve, 'curve');

    throw UnimplementedError('TODO: implement ECDSA');
  }

  static Future<EcdsaPublicKey> importJsonWebKey(
    List<int> jwk,
    EllipticCurve curve,
  ) {
    ArgumentError.checkNotNull(jwk, 'jwk');
    ArgumentError.checkNotNull(curve, 'curve');

    throw UnimplementedError('TODO: implement ECDSA');
  }

  Future<bool> verify(
    List<int> signature,
    Stream<List<int>> data,
    Hasher hasher,
  );

  Future<Uint8List> exportRawKey();

  Future<Uint8List> exportSpkiKey();

  Future<Map<String, Object>> exportJsonWebKey();
}

abstract class RsaOaepPrivateKey {
  RsaOaepPrivateKey._(); // keep the constructor private.

  static Future<RsaOaepPrivateKey> importPkcs8Key(
    List<int> keyData,
    Hasher hasher,
  ) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(hasher, 'hasher');

    throw UnimplementedError('TODO: implement RSA-OAEP');
  }

  static Future<RsaOaepPrivateKey> importJsonWebKey(
    List<int> jwk,
    Hasher hasher,
  ) {
    ArgumentError.checkNotNull(jwk, 'jwk');
    ArgumentError.checkNotNull(hasher, 'hasher');

    throw UnimplementedError('TODO: implement RSA-OAEP');
  }

  static Future<KeyPair<RsaOaepPrivateKey, RsaPssPublicKey>> generateKey(
    int modulusLength,
    BigInt publicExponent,
    Hasher hasher,
  ) {
    ArgumentError.checkNotNull(modulusLength, 'modulusLength');
    ArgumentError.checkNotNull(publicExponent, 'publicExponent');
    ArgumentError.checkNotNull(hasher, 'hasher');

    throw UnimplementedError('TODO: implement RSA-OAEP');
  }

  Stream<Uint8List> decrypt(Stream<List<int>> data, {List<int> label});

  Future<Uint8List> exportPkcs8Key();

  Future<Map<String, Object>> exportJsonWebKey();
}

abstract class RsaOaepPublicKey {
  RsaOaepPublicKey._(); // keep the constructor private.

  static Future<RsaOaepPublicKey> importSpkiKey(
    List<int> keyData,
    Hasher hasher,
  ) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(hasher, 'hasher');

    throw UnimplementedError('TODO: implement RSA-OAEP');
  }

  static Future<RsaOaepPublicKey> importJsonWebKey(
    List<int> jwk,
    Hasher hasher,
  ) {
    ArgumentError.checkNotNull(jwk, 'jwk');
    ArgumentError.checkNotNull(hasher, 'hasher');

    throw UnimplementedError('TODO: implement RSA-OAEP');
  }

  Stream<Uint8List> encrypt(Stream<List<int>> data, {List<int> label});

  Future<Uint8List> exportSpkiKey();

  Future<Map<String, Object>> exportJsonWebKey();
}

abstract class AesCtrSecretKey {
  AesCtrSecretKey._(); // keep the constructor private.

  static Future<AesCtrSecretKey> importRawKey(List<int> keyData) {
    ArgumentError.checkNotNull(keyData, 'keyData');

    throw UnimplementedError('TODO: implement AES-CTR');
  }

  static Future<AesCtrSecretKey> importJsonWebKey(List<int> jwk) {
    ArgumentError.checkNotNull(jwk, 'jwk');

    throw UnimplementedError('TODO: implement AES-CTR');
  }

  static Future<AesCtrSecretKey> generateKey(
    int length,
    // QUESTION: This accepts 128, 192, 256, should we use an enum instead?
    //           (obviously, more values might be acceptable in the future)
    //           Or would separate methods be better, downside is that it
    //           deviates from how other generateKey methods work.
  ) {
    ArgumentError.checkNotNull(length, 'length');

    throw UnimplementedError('TODO: implement AES-CTR');
  }

  Stream<Uint8List> encrypt(
    Stream<List<int>> data,
    List<int> counter,
    int length,
  );

  Stream<Uint8List> decrypt(
    Stream<List<int>> data,
    List<int> counter,
    int length,
  );

  Future<Uint8List> exportRawKey();

  Future<Map<String, Object>> exportJsonWebKey();
}

abstract class AesCbcSecretKey {
  AesCbcSecretKey._(); // keep the constructor private.

  static Future<AesCbcSecretKey> importRawKey(List<int> keyData) {
    ArgumentError.checkNotNull(keyData, 'keyData');

    throw UnimplementedError('TODO: implement AES-CBC');
  }

  static Future<AesCbcSecretKey> importJsonWebKey(List<int> jwk) {
    ArgumentError.checkNotNull(jwk, 'jwk');

    throw UnimplementedError('TODO: implement AES-CBC');
  }

  static Future<AesCbcSecretKey> generateKey(int length) {
    ArgumentError.checkNotNull(length, 'length');

    throw UnimplementedError('TODO: implement AES-CBC');
  }

  Stream<Uint8List> encrypt(Stream<List<int>> data, List<int> iv);

  Stream<Uint8List> decrypt(Stream<List<int>> data, List<int> iv);

  Future<Uint8List> exportRawKey();

  Future<Map<String, Object>> exportJsonWebKey();
}

abstract class AesGcmSecretKey {
  AesGcmSecretKey._(); // keep the constructor private.

  static Future<AesGcmSecretKey> importRawKey(List<int> keyData) {
    ArgumentError.checkNotNull(keyData, 'keyData');

    throw UnimplementedError('TODO: implement AES-GCM');
  }

  static Future<AesGcmSecretKey> importJsonWebKey(List<int> jwk) {
    ArgumentError.checkNotNull(jwk, 'jwk');

    throw UnimplementedError('TODO: implement AES-GCM');
  }

  static Future<AesGcmSecretKey> generateKey(int length) {
    ArgumentError.checkNotNull(length, 'length');

    throw UnimplementedError('TODO: implement AES-GCM');
  }

  Stream<Uint8List> encrypt(
    Stream<List<int>> data,
    List<int> iv, {
    List<int> additionalData,
    int tagLength = 128,
  });

  Stream<Uint8List> decrypt(
    Stream<List<int>> data,
    List<int> iv, {
    List<int> additionalData,
    int tagLength = 128,
  });

  Future<Uint8List> exportRawKey();

  Future<Map<String, Object>> exportJsonWebKey();
}

abstract class EcdhPrivateKey {
  EcdhPrivateKey._(); // keep the constructor private.

  static Future<EcdhPrivateKey> importPkcs8Key(
    List<int> keyData,
    EllipticCurve curve,
  ) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(curve, 'curve');

    throw UnimplementedError('TODO: implement ECDH');
  }

  static Future<EcdhPrivateKey> importJsonWebKey(
    List<int> jwk,
    EllipticCurve curve,
  ) {
    ArgumentError.checkNotNull(jwk, 'jwk');
    ArgumentError.checkNotNull(curve, 'curve');

    throw UnimplementedError('TODO: implement ECDH');
  }

  static Future<KeyPair<EcdhPrivateKey, EcdhPublicKey>> generateKey(
    EllipticCurve curve,
  ) {
    ArgumentError.checkNotNull(curve, 'curve');

    throw UnimplementedError('TODO: implement ECDH');
  }

  Future<Uint8List> deriveBits(EcdhPublicKey publicKey, int length);

  Future<Uint8List> exportPkcs8Key();

  Future<Map<String, Object>> exportJsonWebKey();
}

abstract class EcdhPublicKey {
  EcdhPublicKey._(); // keep the constructor private.

  static Future<EcdhPublicKey> importRawKey(
    List<int> keyData,
    EllipticCurve curve,
  ) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(curve, 'curve');

    throw UnimplementedError('TODO: implement ECDH');
  }

  static Future<EcdhPublicKey> importSpkiKey(
    List<int> keyData,
    EllipticCurve curve,
  ) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(curve, 'curve');

    throw UnimplementedError('TODO: implement ECDH');
  }

  static Future<EcdhPublicKey> importJsonWebKey(
    List<int> jwk,
    EllipticCurve curve,
  ) {
    ArgumentError.checkNotNull(jwk, 'jwk');
    ArgumentError.checkNotNull(curve, 'curve');

    throw UnimplementedError('TODO: implement ECDH');
  }

  Future<Uint8List> exportRawKey();

  Future<Uint8List> exportSpkiKey();

  Future<Map<String, Object>> exportJsonWebKey();
}

abstract class HkdfSecretKey {
  HkdfSecretKey._(); // keep the constructor private.

  static Future<HkdfSecretKey> importRawKey(List<int> keyData) {
    ArgumentError.checkNotNull(keyData, 'keyData');

    throw UnimplementedError('TODO: implement HKDF');
  }

  Future<Uint8List> deriveBits(
    Hasher hasher,
    List<int> salt,
    List<int> info,
  );
}

abstract class Pbkdf2SecretKey {
  Pbkdf2SecretKey._(); // keep the constructor private.

  static Future<Pbkdf2SecretKey> importRawKey(List<int> keyData) {
    ArgumentError.checkNotNull(keyData, 'keyData');

    throw UnimplementedError('TODO: implement PBKDF2');
  }

  Future<Uint8List> deriveBits(
    Hasher hasher,
    List<int> salt,
    int iterations,
  );
}
