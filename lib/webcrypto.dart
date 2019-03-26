/// _The `webcrypto` package provides bindings for
/// [web cryptography API][webcrypto-spec]._
///
/// Cryptographic primitives stores the key material in algorithm-specific
/// [CryptoKey] subclasses such as [HmacSecretKey]. Instances of these keys
/// is _always_ created using asynchronous static methods on the [CryptoKey]
/// subclass in question. For example, a [HmacSecretKey] can be created using
/// [HmacSecretKey.generateKey()] and [HmacSecretKey.importRawKey()].
///
/// For algorithms with both private and public keys static the method to
/// generate a [CryptoKeyPair] with both a private and public key is exposed as
/// a static method on the [CryptoKey] subclass for the private key.
/// For example, [RsassaPkcs1V15PrivateKey.generateKey()] generates both a
/// public and a private key.
///
/// Once instantiated a [CryptoKey] subclass is immutable. The capabilities of
/// the [CryptoKey] instance is configured when it is imported or generated.
/// Methods to import or generate a [CryptoKey] subclass accepts a boolean
/// `extractable` and a [List<KeyUsage>] `usages`, together these determine
/// which operations are permitted. This aims to prevent unintended usage of
/// keys.
///
/// **Warning**, this package provides access cryptographic primitives. Using
/// these correctly is non-trivial and subtle mistakes can cause security
/// vulnerabilities in your application.
/// **If you are unsure how these cryptographic primitives work, it is wise to
/// consult a security expert.**
///
/// ## Supported Platforms
/// The functionality available in this package works is design to be available
/// everywhere Dart runs.
///
/// In the browser the computation delegated to the browser's
/// [Web Cryptography][webcrypto-spec] implementation, which is available in
/// recent versions of most modern browsers. If necessary shims can be employed
/// to reach all browsers, however, distribution of such shims is outside the
/// scope of this package.
///
/// In the Dart VM and AOT compiled Dart code, the computation is delegated to
/// [BoringSSL][boringssl], which is also used by the Dart SDK for TLS
/// connections.
///
/// [webcrypto-spec]: https://www.w3.org/TR/WebCryptoAPI/
/// [boringssl]: https://boringssl.googlesource.com/boringssl/
library webcrypto;

import 'dart:async';
import 'dart:typed_data';
import 'package:meta/meta.dart';

import 'src/webcrypto_impl_stub.dart'
    if (dart.library.ffi) 'src/webcrypto_impl_ffi.dart'
    if (dart.library.io) 'src/webcrypto_impl_native.dart'
    if (dart.library.html) 'src/webcrypto_impl_browser.dart' as impl;
import 'src/utils.dart' as utils;
import 'src/cryptokey.dart';

export 'src/exceptions.dart';
export 'src/cryptokey.dart';

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
/// getRandomValues(bytes);
///
/// // Print base64 encoded random bytes.
/// print(base64.encode(bytes));
/// ```
void getRandomValues(TypedData destination) {
  ArgumentError.checkNotNull(destination, 'destination');
  // This limitation is given in the Web Cryptography Specification, see:
  // https://www.w3.org/TR/WebCryptoAPI/#Crypto-method-getRandomValues
  if (destination.lengthInBytes > 65536) {
    throw ArgumentError.value(destination, 'destination',
        'array of more than 65536 bytes is not allowed');
  }

  impl.getRandomValues(destination);
}

/// A hash algorithm supported by other methods in this package.
///
/// See [digest] for how to compute the hash sum of a byte stream.
enum HashAlgorithm {
  // TODO: Consider renaming this type `Hash` instead of `HashAlgorithm`

  /// SHA-1 as specified in [FIPS PUB 180-4][1].
  ///
  /// **This algorithm is considered weak** and should not be used in new
  /// cryptographic applications.
  ///
  /// [1]: https://doi.org/10.6028/NIST.FIPS.180-4
  sha1,

  /// SHA-256 as specified in [FIPS PUB 180-4][1].
  ///
  /// [1]: https://doi.org/10.6028/NIST.FIPS.180-4
  sha256,

  /// SHA-384 as specified in [FIPS PUB 180-4][1].
  ///
  /// [1]: https://doi.org/10.6028/NIST.FIPS.180-4
  sha384,

  /// SHA-512 as specified in [FIPS PUB 180-4][1].
  ///
  /// [1]: https://doi.org/10.6028/NIST.FIPS.180-4
  sha512,
}

/// Compute a cryptographic hash-sum of [data] stream using [hash].
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
/// List<int> hash = await digest(
///   hash: HashAlgorithm.sha256,
///   data: File(fileToHash).openRead(),
/// );
///
/// // Print the base64 encoded hash
/// print(base64.encode(hash));
/// ```
///
/// This package does not provide a convenient function for hashing a
/// byte array. But as illustrated in the example below this can be achieved by
/// creating a function that wraps the byte array in a byte stream.
///
/// **Example**
/// ```dart
/// import 'dart:convert' show base64, utf8;
/// import 'package:webcrypto/webcrypto.dart';
///
/// // Function that creates a stream of data we can hash.
/// Stream<List<int>> dataStream() async* {
///   // In this case our stream contains a single chunk of bytes.
///   yield utf8.encode('hello world');
/// }
///
/// // Compute hash of the dataStream with sha-256
/// List<int> hash = await digest(
///   hash: HashAlgorithm.sha256,
///   data: dataStream(),
/// );
///
/// // Print the base64 encoded hash
/// print(base64.encode(hash));
/// ```
Future<List<int>> digest({
  // Note: It's tempting to use positional arguments, but this could cause
  //       problems if future iterations of the Web Cryptography Specification
  //       defines new digest algorithms with additional parameters.
  //       meta-note: I could probably convinced otherwise too.
  @required HashAlgorithm hash,
  @required Stream<List<int>> data,
}) {
  ArgumentError.checkNotNull(hash, 'hash');
  ArgumentError.checkNotNull(data, 'data');

  return impl.digest(hash: hash, data: data);
}

/// Check that [usages] is a subset of [allowedUsages], throws an
/// [ArgumentError] if:
///  * [usages] is `null`
///  * [usages] is not a subset of [allowedUsages].
///
/// The [algorithm] paramter is used specify a string that will be used in the
/// error message explaining why a given usage is not allowed.
void _checkAllowedUsages(
  String algorithm,
  List<KeyUsage> usages,
  List<KeyUsage> allowedUsages,
) {
  ArgumentError.checkNotNull(usages, 'usages');
  assert(algorithm != null && algorithm != '', 'algorithm should be given');
  assert(allowedUsages != null, 'allowedUsages should be given');

  for (final usage in usages) {
    if (!allowedUsages.contains(usage)) {
      final allowedList = allowedUsages.map(utils.keyUsageToString).join(', ');
      throw ArgumentError.value(
          usage, 'usages', '$algorithm only supports usages $allowedList');
    }
  }
}

/// Remove duplicate [usages] and sort according to index in enum.
List<KeyUsage> _normalizeUsages(List<KeyUsage> usages) {
  assert(usages != null, 'usages should be checked for null');
  usages = usages.toSet().toList();
  usages.sort((a, b) => a.index.compareTo(b.index));
  return usages;
}

/// Key for signing/verifying with HMAC.
///
/// An [HmacSecretKey] instance holds a symmetric secret key and a
/// [HashAlgorithm], which can be used to create and verify HMAC signatures as
/// specified in [FIPS PUB 180-4][1].
///
/// Instances of [HmacSecretKey] can be imported using
/// [HmacSecretKey.importRawKey] or generated using [HmacSecretKey.generateKey].
///
/// [1]: https://doi.org/10.6028/NIST.FIPS.180-4
abstract class HmacSecretKey implements CryptoKey {
  /// Import [HmacSecretKey] from raw [keyData].
  ///
  /// Creates an [HmacSecretKey] using [keyData] as secret key, and running
  /// HMAC with given [hash] algorithm. Valid [usages] is [KeyUsage.sign] and
  /// [KeyUsage.verify].
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
  ///   keyData: utf8.encode('a-secret-key'),  // don't use string in practice
  ///   hash: HashAlgorithm.sha256,
  ///   extractable: false,
  ///   usages: [KeyUsage.sign],
  /// );
  /// ```
  static Future<HmacSecretKey> importRawKey({
    @required List<int> keyData,
    @required HashAlgorithm hash,
    @required bool extractable,
    @required List<KeyUsage> usages,
    int length,
  }) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(hash, 'hash');
    ArgumentError.checkNotNull(extractable, 'extractable');
    _checkAllowedUsages('HMAC', usages, [
      KeyUsage.sign,
      KeyUsage.verify,
    ]);
    usages = _normalizeUsages(usages);
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

    return impl.hmacSecret_importRawKey(
      keyData: keyData,
      extractable: extractable,
      usages: usages,
      hash: hash,
      length: length,
    );
  }

  /// Generate random [HmacSecretKey].
  ///
  /// The [length] specifies the length of the secret key in bits. If omitted
  /// the random key will use the same number of bits as the underlying hash
  /// algorithm given in [hash].
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate a new random HMAC secret key.
  /// final key = await HmacSecretKey.generate({
  ///   hash: HashAlgorithm.sha256,
  ///   extractable: true,
  ///   usages: [KeyUsage.sign, KeyUsage.verify],
  /// });
  /// ```
  static Future<HmacSecretKey> generateKey({
    @required HashAlgorithm hash,
    @required bool extractable,
    @required List<KeyUsage> usages,
    int length,
  }) {
    ArgumentError.checkNotNull(hash, 'hash');
    ArgumentError.checkNotNull(extractable, 'extractable');
    _checkAllowedUsages('HMAC', usages, [
      KeyUsage.sign,
      KeyUsage.verify,
    ]);
    usages = _normalizeUsages(usages);
    if (length != null && length <= 0) {
      throw ArgumentError.value(length, 'length', 'must be positive');
    }

    return impl.hmacSecret_generateKey(
      extractable: extractable,
      usages: usages,
      hash: hash,
      length: length,
    );
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
  /// final key = await HmacSecretKey.generateKey(
  ///   hash: HashAlgorithm.sha256,
  ///   extractable: true,
  ///   usages: [KeyUsage.sign, KeyUsage.verify],
  /// );
  ///
  /// // Function that creates a stream of data from our string-to-sign:
  /// String stringToSign = 'example-string-to-signed';
  /// Stream<List<int>> dataStream() async* {
  ///   yield utf8.encode(stringToSign);
  /// }
  ///
  /// // Compute signature.
  /// final signature = await key.sign(data: dataStream());
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
  Future<List<int>> sign({
    @required Stream<List<int>> data,
  });

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
  /// final key = await HmacSecretKey.generateKey(
  ///   hash: HashAlgorithm.sha256,
  ///   extractable: true,
  ///   usages: [KeyUsage.sign, KeyUsage.verify],
  /// );
  ///
  /// // Function that creates a stream of data from our string-to-sign:
  /// String stringToSign = 'example-string-to-signed';
  /// Stream<List<int>> dataStream() async* {
  ///   yield utf8.encode(stringToSign);
  /// }
  ///
  /// // Compute signature.
  /// final signature = await key.sign(data: dataStream());
  ///
  /// // Verify signature.
  /// final result = await key.verify(signature: signature, data: dataStream());
  /// assert(result == true, 'this signature should be valid');
  /// ```
  Future<bool> verify({
    @required List<int> signature,
    @required Stream<List<int>> data,
  });

  /// Export [HmacSecretKey] as raw bytes.
  ///
  /// This returns raw bytes making up the secret key. This does not encode the
  /// [HashAlgorithm], [usages], [extractable] or other metadata the key was
  /// created with. This operation requires this key to be [extractable].
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate a new random HMAC secret key.
  /// final key = await HmacSecretKey.generate({
  ///   hash: HashAlgorithm.sha256,
  ///   extractable: true,
  ///   usages: [KeyUsage.sign, KeyUsage.verify],
  /// });
  ///
  /// // Extract the secret key.
  /// final secretBytes = await key.extractRawKey();
  ///
  /// // Print the key as base64
  /// print(base64.encode(secretBytes));
  ///
  /// // If we wanted to we could import the key as follows:
  /// // key = await HmacSecretKey.importRawKey({
  /// //   keyData: secretBytes,
  /// //   hash: HashAlgorithm.sha256,
  /// //   extractable: true,
  /// //   usages: [KeyUsage.sign, KeyUsage.verify],
  /// // });
  /// ```
  Future<List<int>> exportRawKey();
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
abstract class RsassaPkcs1V15PrivateKey implements CryptoKey {
  /// Import RSASSA-PKCS1-v1_5 private key in PKCS #8 format.
  ///
  /// Creates an [RsassaPkcs1V15PrivateKey] from [keyData] given as the DER
  /// encoding of the _PrivateKeyInfo structure_ specified in [RFC 5208][1].
  /// The [HashAlgorithm] to be used is specified by [hash]. The only valid
  /// [usages] is [KeyUsage.sign].
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
  ///   keyData: keyData,
  ///   hash: HashAlgorithm.sha256,
  ///   extractable: true,
  ///   usages: [KeyUsage.sign],
  /// );
  ///
  /// // Export the key again (print it in same format as it was given).
  /// List<int> rawKeyData = await privateKey.exportPkcs8Key();
  /// print(PemCodec(PemLabel.privateKey).encode(rawKeyData));
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc5208
  static Future<RsassaPkcs1V15PrivateKey> importPkcs8Key({
    @required List<int> keyData,
    @required bool extractable,
    @required List<KeyUsage> usages,
    @required HashAlgorithm hash,
  }) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(extractable, 'extractable');
    _checkAllowedUsages('RSASSA_PKCS1_v1_5', usages, [KeyUsage.sign]);
    usages = _normalizeUsages(usages);
    ArgumentError.checkNotNull(hash, 'hash');

    return impl.rsassaPkcs1V15PrivateKey_importPkcs8Key(
      keyData: keyData,
      extractable: extractable,
      usages: usages,
      hash: hash,
    );
  }

  /// Generate an RSASSA-PKCS1-v1_5 public/private key-pair.
  ///
  /// Generate an RSA key with given [modulusLength], this should be at-least
  /// `2048` (though `4096` is often recommended). [publicExponent] should be
  /// `3` or `65537` these are the only values [supported by Chrome][1], unless
  /// you have a good reason to use something else `65537` is recommended.
  ///
  /// The [HashAlgorithm] to be used is specified by [hash]. The only valid
  /// [usages] is [KeyUsage.sign] and [KeyUsage.verify]. The [extractable] bit
  /// determines if the generated keys can be extracted later.
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'package:pem/pem.dart';
  ///
  /// // Generate a key-pair.
  /// final keyPair = await RsassaPkcs1V15PrivateKey.generateKey(
  ///   modulusLength: 4096,
  ///   publicExponent: BigInt.from(65537),
  ///   hash: HashAlgorithm.sha256,
  ///   extractable: true,
  ///   usages: [KeyUsage.sign, KeyUsage.verify],
  /// );
  ///
  /// // Export public, so Alice can use it later.
  /// final rawPublicKey = await keyPair.publicKey.exportSpkiKey();
  /// final pemPublicKey = PemCodec(PemLabel.publicKey).encode(rawPublicKey);
  /// print(pemPublicKey); // print key in PEM format: -----BEGIN PUBLIC KEY....
  ///
  /// // Sign a message for Alice.
  /// final message = 'Hi Alice';
  /// final signature = await keyPair.privateKey.sign(data: () async* {
  ///   yield utf8.encode(message);
  /// }());
  ///
  /// // On the other side of the world, Alice has written down the pemPublicKey
  /// // on a trusted piece of paper, but receives the message and signature
  /// // from an untrusted source (thus, desires to verify the signature).
  /// final publicKey = await RsassaPkcs1V15PublicKey.importSpkiKey(
  ///   keyData: PemCodec(PemLabel.publicKey).decode(pemPublicKey),
  ///   hash: HashAlgorithm.sha256,
  ///   extractable: false,
  ///   usages: [KeyUsage.verify],
  /// );
  /// final isValid = await publicKey.verify(
  ///   signature: signature,
  ///   data: () async* {
  ///     yield utf8.encode(message);
  ///   }(),
  /// );
  /// if (isValid) {
  ///   print('Authentic message from Bob: $message');
  /// }
  /// ```
  ///
  /// [1]: https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/rsa.cc#286
  static Future<
          CryptoKeyPair<RsassaPkcs1V15PrivateKey, RsassaPkcs1V15PublicKey>>
      generateKey({
    @required int modulusLength,
    @required BigInt publicExponent,
    @required HashAlgorithm hash,
    @required bool extractable,
    @required List<KeyUsage> usages,
  }) {
    ArgumentError.checkNotNull(modulusLength, 'modulusLength');
    ArgumentError.checkNotNull(publicExponent, 'publicExponent');
    ArgumentError.checkNotNull(hash, 'hash');
    ArgumentError.checkNotNull(extractable, 'extractable');
    _checkAllowedUsages('RSASSA_PKCS1_v1_5', usages, [
      KeyUsage.sign,
      KeyUsage.verify,
    ]);
    usages = _normalizeUsages(usages);

    return impl.rsassaPkcs1V15PrivateKey_generateKey(
      modulusLength: modulusLength,
      publicExponent: publicExponent,
      hash: hash,
      extractable: extractable,
      usages: usages,
    );
  }

  /// Sign [data] with this RSASSA-PKCS1-v1_5 private key.
  ///
  /// Returns a signature as a list of raw bytes. This uses the [HashAlgorithm]
  /// specified when the key was generated or imported. To use this operation
  /// the key must have been imported or generated with [KeyUsage.sign].
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
  ///   keyData: keyData,
  ///   extractable: false,
  ///   usages: [KeyUsage.sign],
  ///   hash: HashAlgorithm.sha256,
  /// );
  ///
  /// // Create a signature for UTF-8 encoded message
  /// final message = 'hello world';
  /// final signature = await privateKey.sign(data: () async* {
  ///   yield utf8.encode(message);
  /// }());
  /// print('signature: ${base64.encode(signature)}');
  /// ```
  Future<List<int>> sign({
    @required Stream<List<int>> data,
  });

  /// Export this RSASSA-PKCS1-v1_5 private key in PKCS #8 format.
  ///
  /// Returns the DER encoding of the _PrivateKeyInfo structure_ specified in
  /// [RFC 5208][1] as a list of bytes. This operation is only allowed if the
  /// key was imported or generated with the [extractable] bit set to `true`.
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'package:pem/pem.dart';
  ///
  /// // Generate a key-pair.
  /// final keyPair = await RsassaPkcs1V15PrivateKey.generateKey(
  ///   modulusLength: 4096,
  ///   publicExponent: BigInt.from(65537),
  ///   hash: HashAlgorithm.sha256,
  ///   extractable: true,
  ///   usages: [],
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
  Future<List<int>> exportPkcs8Key();
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
abstract class RsassaPkcs1V15PublicKey implements CryptoKey {
  /// Import RSASSA-PKCS1-v1_5 public key in SPKI format.
  ///
  /// Creates an [RsassaPkcs1V15PublicKey] from [keyData] given as the DER
  /// encoding of the _SubjectPublicKeyInfo structure_ specified in
  /// [RFC 5280][1]. The [HashAlgorithm] to be used is specified by [hash]. The
  /// only valid [usages] is [KeyUsage.verify].
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
  ///   keyData: keyData,
  ///   hash: HashAlgorithm.sha256,
  ///   extractable: true,
  ///   usages: [KeyUsage.verify],
  /// );
  ///
  /// // Export the key again (print it in same format as it was given).
  /// List<int> rawKeyData = await publicKey.exportSpkiKey();
  /// print(PemCodec(PemLabel.publicKey).encode(rawKeyData));
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc5280
  static Future<RsassaPkcs1V15PublicKey> importSpkiKey({
    @required List<int> keyData,
    @required HashAlgorithm hash,
    @required bool extractable,
    @required List<KeyUsage> usages,
  }) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(extractable, 'extractable');
    _checkAllowedUsages('RSASSA_PKCS1_v1_5', usages, [KeyUsage.verify]);
    usages = _normalizeUsages(usages);
    ArgumentError.checkNotNull(hash, 'hash');

    return impl.rsassaPkcs1V15PublicKey_importSpkiKey(
      keyData: keyData,
      extractable: extractable,
      usages: usages,
      hash: hash,
    );
  }

  /// Verify [signature] of [data] using this RSASSA-PKCS1-v1_5 public key.
  ///
  /// Returns `true` if the signature was made the private key matching this
  /// public key. This uses the [HashAlgorithm] specified when the key was
  /// generated or imported. To use this operation the key must have been
  /// imported or generated with [KeyUsage.verify].
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate a key-pair.
  /// final keyPair = await RsassaPkcs1V15PrivateKey.generateKey(
  ///   modulusLength: 4096,
  ///   publicExponent: BigInt.from(65537),
  ///   hash: HashAlgorithm.sha256,
  ///   extractable: false,
  ///   usages: [KeyUsage.sign, KeyUsage.verify],
  /// );
  ///
  /// // Using privateKey Bob can sign a message for Alice.
  /// final message = 'Hi Alice';
  /// final signature = await keyPair.privateKey.sign(data: () async* {
  ///   yield utf8.encode(message);
  /// }());
  ///
  /// // Given publicKey and signature Alice can verify the message from Bob.
  /// final isValid = await keypair.publicKey.verify(
  ///   signature: signature,
  ///   data: () async* {
  ///     yield utf8.encode(message);
  ///   }(),
  /// );
  /// if (isValid) {
  ///   print('Authentic message from Bob: $message');
  /// }
  /// ```
  Future<bool> verify({
    @required List<int> signature,
    @required Stream<List<int>> data,
  });

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
  ///   modulusLength: 4096,
  ///   publicExponent: BigInt.from(65537),
  ///   hash: HashAlgorithm.sha256,
  ///   extractable: true,
  ///   usages: [],
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
  Future<List<int>> exportSpkiKey();
}
