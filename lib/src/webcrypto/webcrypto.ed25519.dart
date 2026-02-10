part of 'webcrypto.dart';

/// Ed25519 private key for signing messages.
///
/// An [Ed25519PrivateKey] instance holds a private key for computing
/// signatures using the EdDSA scheme as specified in [RFC 8032][1].
///
/// An [Ed25519PrivateKey] can be imported from:
/// * PKCS8 Key using [Ed25519PrivateKey.importPkcs8Key], and,
/// * JSON Web Key using [Ed25519PrivateKey.importJsonWebKey].
///
/// A public-private [KeyPair] consisting of a [Ed25519PublicKey] and a
/// [Ed25519PrivateKey] can be generated using [Ed25519PrivateKey.generateKey].
///
/// {@template Ed25519-Example:generate-sign-verify}
/// **Example**
/// ```dart
/// import 'dart:convert' show utf8;
/// import 'package:webcrypto/webcrypto.dart';
///
/// // Generate a key-pair.
/// final keyPair = await Ed25519PrivateKey.generateKey();
///
/// // Using privateKey Bob can sign a message for Alice.
/// final message = 'Hi Alice';
/// final signature = await keyPair.privateKey.signBytes(utf8.encode(message));
///
/// // Given publicKey and signature Alice can verify the message from Bob.
/// final isValid = await keypair.publicKey.verifyBytes(
///   signature,
///   utf8.encode(message),
/// );
/// if (isValid) {
///   print('Authentic message from Bob: $message');
/// }
/// ```
/// {@endtemplate}
///
/// [1]: https://datatracker.ietf.org/doc/html/rfc8032
final class Ed25519PrivateKey {
  final Ed25519PrivateKeyImpl _impl;

  Ed25519PrivateKey._(this._impl);

  /// Import [Ed25519PrivateKey] in the [PKCS #8][1] format.
  ///
  /// Creates an [Ed25519PrivateKey] from [keyData] given as the DER encodeding
  /// _PrivateKeyInfo structure_ specified in [RFC 5208][1].
  ///
  /// **Example**
  /// ```dart
  /// import 'package:pem/pem.dart';
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Read key data from a PEM encoded block. This will remove the
  /// // the padding, decode base64 and return the encoded bytes.
  /// List<int> keyData = PemCodec(PemLabel.privateKey).decode('''
  ///   -----BEGIN PRIVATE KEY-----
  ///   MC4CAQAwBQYDK2VuBCI.....
  ///   -----END PRIVATE KEY-----
  ///   ''');
  ///
  ///
  /// Future<void> main() async {
  ///   // Import the Private Key from a Binary PEM decoded data.
  ///   final privateKey = await Ed25519PrivateKey.importPkcs8Key(keyData);
  ///
  ///  // Export the private key (print it in same format as it was given).
  ///  final exportedPkcs8Key = await privateKey.exportPkcs8Key();
  ///  print(PemCodec(PemLabel.privateKey).encode(exportedPkcs8Key));
  /// }
  /// ```
  ///
  /// [1]: https://datatracker.ietf.org/doc/html/rfc5208
  static Future<Ed25519PrivateKey> importPkcs8Key(List<int> keyData) async {
    final impl = await webCryptImpl.ed25519PrivateKey.importPkcs8Key(keyData);
    return Ed25519PrivateKey._(impl);
  }

  /// Import Ed25519 private key in [JSON Web Key][1] format.
  ///
  /// {@macro importJsonWebKey:jwk}
  ///
  /// JSON Web Keys imported using [Ed25519PrivateKey.importJsonWebKey] must
  /// have the following parameters as described in [RFC 8037][2]:
  /// * `"kty"`: The key type must be `"OKP"`.
  /// * `"crv"`: The curve parameter must be `"Ed25519"`.
  /// * `"alg"`: The alg parameter must be `"Ed25519"` or `"EdDSA"`, if present.
  /// * `"x"`: The x parameter must be present and contain the public key
  /// encoded as a [base64Url] encoded string.
  /// * `"d"`: The d parameter must be present for private keys and contain the
  /// private key encoded as a [base64Url] encoded string.
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // JSON Web Key as map representing the decoded JSON.
  /// final jwk = {
  ///   'kty': 'OKP',
  ///   'crv': 'Ed25519',
  ///   'x': 'coeKtJr7mBuIBzGjR_T4OFfuU3Sn85-frLUvxzg5320',
  ///   'd': '0iqe8CdaOI0uP_UG7wzEQanilG-UWWw4tuSeMKNXnKA',
  /// };
  ///
  /// Future<void> main() async {
  ///   // Import secret key from decoded JSON.
  ///   final jsonWebKey = await Ed25519PrivateKey.importJsonWebKey(jwk);
  ///
  ///   // Export the key (print it in same format as it was given).
  ///   final exportedJsonWebKey = await jsonWebKey.exportJsonWebKey();
  ///   print(exportedJsonWebKey);
  /// }
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc7517
  /// [2]: https://datatracker.ietf.org/doc/html/rfc8037#section-2
  static Future<Ed25519PrivateKey> importJsonWebKey(
    Map<String, dynamic> jwk,
  ) async {
    final impl = await webCryptImpl.ed25519PrivateKey.importJsonWebKey(jwk);
    return Ed25519PrivateKey._(impl);
  }

  /// Generate a new [Ed25519PrivateKey] and [Ed25519PublicKey] pair.
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// Future<void> main() async {
  ///   // Generate a new Ed25519 key pair.
  ///   final keyPair = await Ed25519PrivateKey.generateKey();
  ///
  ///   // Export the private key.
  ///   final exportedPrivateKey = await keyPair.privateKey.exportJsonWebKey();
  ///   print(exportedPrivateKey);
  ///
  ///   // Export the public key.
  ///   final exportedPublicKey = await keyPair.publicKey.exportJsonWebKey();
  ///   print(exportedPublicKey);
  /// }
  /// ```
  static Future<KeyPair<Ed25519PrivateKey, Ed25519PublicKey>>
      generateKey() async {
    final (privateKeyImpl, publicKeyImpl) =
        await webCryptImpl.ed25519PrivateKey.generateKey();

    final privateKey = Ed25519PrivateKey._(privateKeyImpl);
    final publicKey = Ed25519PublicKey._(publicKeyImpl);

    return (privateKey: privateKey, publicKey: publicKey);
  }

  /// Sign [data] with this [Ed25519PrivateKey].
  ///
  /// Returns a signature as a list of raw bytes.2].
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
  ///   MC4CAQAwBQYDK2VuBCI.....
  ///   -----END PRIVATE KEY-----
  /// """);
  ///
  /// // Import private key from binary PEM decoded data.
  /// final privatKey = await Ed25519PrivateKey.importPkcs8Key(keyData);
  ///
  /// // Create a signature for UTF-8 encoded message
  /// final message = 'hello world';
  /// final signature = await privateKey.signBytes(utf8.encode(message));
  ///
  /// print('signature: ${base64.encode(signature)}');
  /// ```
  Future<Uint8List> signBytes(List<int> data) => _impl.signBytes(data);

  /// Export the [Ed25519PrivateKey] as a [PKCS #8][1] key.
  ///
  /// Returns the DER encoding of the _PrivateKeyInfo_ structure specified in
  /// [RFC 5208][1] as a list of bytes.
  ///
  /// **Example**
  /// ```dart
  /// import 'package:pem/pem.dart';
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// Future<void> main() async {
  ///   // Generate a key-pair
  ///   final kp = await Ed25519PrivateKey.generateKey();
  ///
  ///   // Export the private key.
  ///   final exportedPkcs8Key = await kp.privateKey.exportPkcs8Key();
  ///
  ///   // Private keys are often encoded as PEM.
  ///   // This encodes the key in base64 and wraps it with:
  ///   // '-----BEGIN PRIVATE KEY----'...
  ///   print(PemCodec(PemLabel.privateKey).encode(exportedPkcs8Key));
  /// }
  /// ```
  /// [1]: https://datatracker.ietf.org/doc/html/rfc5208
  Future<Uint8List> exportPkcs8Key() async => _impl.exportPkcs8Key();

  /// Export the [Ed25519PrivateKey] as a [JSON Web Key][1].
  ///
  /// {@macro exportJsonWebKey:returns}
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert';
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// Future<void> main() async {
  ///   // Alice generates a key-pair
  ///   final kpA = await Ed25519PrivateKey.generateKey();
  ///
  ///   // Export the private key as a JSON Web Key.
  ///   final exportedPrivateKey = await kpA.privateKey.exportJsonWebKey();
  ///
  ///   // The Map returned by `exportJsonWebKey()` can be converted to JSON
  ///   // with `jsonEncode` from `dart:convert`.
  ///   print(jsonEncode(exportedPrivateKey));
  /// }
  /// ```
  /// [1]: https://www.rfc-editor.org/rfc/rfc7518.html
  Future<Map<String, dynamic>> exportJsonWebKey() => _impl.exportJsonWebKey();
}

/// Ed25519 public key for verifying signatures.
///
/// An [Ed25519PublicKey] instance holds a public Ed25519 key for verification
/// of signatures using the EdDSA scheme as specified in [RFC 8032][1].
///
/// An [Ed25519PublicKey] can be imported from:
///  * [SPKI][2] format using [Ed25519PublicKey.importSpkiKey], and,
///  * [JWK][3] format using [Ed25519PublicKey.importJsonWebKey].
///
/// A public-private [KeyPair] consisting of a [Ed25519PublicKey] and a
/// [Ed25519PrivateKey] can be generated using [Ed25519PrivateKey.generateKey].
///
/// {@macro Ed25519-Example:generate-sign-verify}
///
/// [1]: https://datatracker.ietf.org/doc/html/rfc8032
/// [2]: https://tools.ietf.org/html/rfc5280
/// [3]: https://tools.ietf.org/html/rfc7517
final class Ed25519PublicKey {
  final Ed25519PublicKeyImpl _impl;

  Ed25519PublicKey._(this._impl);

  static Future<Ed25519PublicKey> importRawKey(List<int> keyData) async {
    final impl = await webCryptImpl.ed25519PublicKey.importRawKey(keyData);
    return Ed25519PublicKey._(impl);
  }

  /// Import Ed25519 public key in SPKI format.
  ///
  /// Creates an [Ed25519PublicKey] from [keyData] given as the DER
  /// encoding of the _SubjectPublicKeyInfo structure_ specified in
  /// [RFC 5280][1].
  ///
  /// Throws [FormatException] if [keyData] is invalid.
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
  ///   MCowBQYDK2VwAyEA...
  ///   -----END PUBLIC KEY-----
  /// """);
  ///
  /// // Import public key from binary PEM decoded data.
  /// final publicKey = await Ed25519PublicKey.importSpkiKey(keyData);
  ///
  /// // Export the key again (print it in same format as it was given).
  /// List<int> rawKeyData = await publicKey.exportSpkiKey();
  /// print(PemCodec(PemLabel.publicKey).encode(rawKeyData));
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc5280
  static Future<Ed25519PublicKey> importSpkiKey(List<int> keyData) async {
    final impl = await webCryptImpl.ed25519PublicKey.importSpkiKey(keyData);
    return Ed25519PublicKey._(impl);
  }

  /// Import Ed25519 public key in [JSON Web Key][1] format.
  ///
  /// {@macro importJsonWebKey:jwk}
  ///
  /// JSON Web Keys imported using [Ed25519PublicKey.importJsonWebKey] must
  /// have the following parameters as described in [RFC 8037][2]:
  /// * `"kty"`: The key type must be `"OKP"`.
  /// * `"crv"`: The curve parameter must be `"Ed25519"`.
  /// * `"x"`: The x parameter must be present and contain the public key
  /// encoded as a [base64Url] encoded string.
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // JSON Web Key as map representing the decoded JSON.
  /// final jwk = {
  ///   'kty': 'OKP',
  ///   'crv': 'Ed25519',
  ///   'x': 'coeKtJr7mBuIBzGjR_T4OFfuU3Sn85-frLUvxzg5320',
  /// };
  ///
  /// Future<void> main() async {
  ///   // Import the public key from decoded JSON.
  ///   final jsonWebKey = await Ed25519PublicKey.importJsonWebKey(jwk);
  ///
  ///   // Export the key (print it in same format as it was given).
  ///   final exportedJsonWebKey = await jsonWebKey.exportJsonWebKey();
  ///   print(exportedJsonWebKey);
  /// }
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc7517
  /// [2]: https://datatracker.ietf.org/doc/html/rfc8037#section-2
  static Future<Ed25519PublicKey> importJsonWebKey(
    Map<String, dynamic> jwk,
  ) async {
    final impl = await webCryptImpl.ed25519PublicKey.importJsonWebKey(jwk);
    return Ed25519PublicKey._(impl);
  }

  /// Verify [signature] of [data] using this Ed25519 public key.
  ///
  /// Returns `true` if the signature was made the private key matching this
  /// public key.
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate a key-pair.
  /// final keyPair = await Ed25519PrivateKey.generateKey();
  ///
  /// // Using privateKey Bob can sign a message for Alice.
  /// final message = 'Hi Alice';
  /// final signature = await keyPair.privateKey.signBytes(
  ///   utf8.encode(message),
  /// );
  ///
  /// // Given publicKey and signature Alice can verify the message from Bob.
  /// final isValid = await keypair.publicKey.verifyBytes(
  ///   signature,
  ///   utf8.encode(message),
  /// );
  /// if (isValid) {
  ///   print('Authentic message from Bob: $message');
  /// }
  /// ```
  Future<bool> verifyBytes(List<int> signature, List<int> data) =>
      _impl.verifyBytes(signature, data);

  /// Export Ed25519 public key as a raw list of bytes.
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Generate a key-pair.
  /// final keyPair = await Ed25519PrivateKey.generateKey();
  ///
  /// // Export the public key as raw bytes.
  /// final rawPublicKey = await keyPair.publicKey.exportRawKey();
  Future<Uint8List> exportRawKey() => _impl.exportRawKey();

  /// Export Ed25519 public key in SPKI format.
  ///
  /// Returns the DER encoding of the _SubjectPublicKeyInfo structure_ specified
  /// in [RFC 5280][1] as a list of bytes.
  ///
  /// **Example**
  /// ```dart
  /// import 'package:webcrypto/webcrypto.dart';
  /// import 'package:pem/pem.dart';
  ///
  /// // Generate a key-pair.
  /// final keyPair = await Ed25519PrivateKey.generateKey();
  ///
  /// // Export the public key.
  /// final spkiPublicKey = await keyPair.publicKey.exportSpkiKey();
  ///
  /// // Public keys are often encoded as PEM.
  /// // This encode the key in base64 and wraps it with:
  /// // '-----BEGIN PUBLIC KEY-----'...
  /// print(PemCodec(PemLabel.publicKey).encode(spkiPublicKey));
  /// ```
  ///
  /// [1]: https://tools.ietf.org/html/rfc5280
  Future<Uint8List> exportSpkiKey() => _impl.exportSpkiKey();

  /// Export the [Ed25519PublicKey] as a [JSON Web Key][1].
  ///
  /// {@macro exportJsonWebKey:returns}
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert';
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Public JSON Web Key data.
  /// final jwk = {
  ///   'kty': 'OKP',
  ///   'crv': 'Ed25519',
  ///   'x': 'coeKtJr7mBuIBzGjR_T4OFfuU3Sn85-frLUvxzg5320',
  /// };
  ///
  /// Future<void> main() async {
  ///   // Import Alice's public key
  ///   final pkA = await Ed25519PublicKey.importJsonWebKey(jwk);
  ///
  ///   // Export the public key as a JSON Web Key.
  ///   final exportedPublicKey = await pkA.exportJsonWebKey();
  ///
  ///   // The Map returned by `exportJsonWebKey()` can be converted to JSON
  ///   // with `jsonEncode` from `dart:convert`.
  ///   print(jsonEncode(exportedPublicKey));
  /// }
  /// ```
  /// [1]: https://www.rfc-editor.org/rfc/rfc7518.html
  Future<Map<String, dynamic>> exportJsonWebKey() => _impl.exportJsonWebKey();
}
