/// Operation kinds for which a key can be used.
///
/// When a [CryptoKey] is imported or generated a list of _usages_ allows the
/// caller to specify what operations the key can be used to perform. This
/// allows the caller to prevent unintended misuse of the key.
///
/// For example if an [HmacSecretKey] is used to verify incoming request
/// signatures it is necessary to grant [KeyUsage.verify]. But it might be wise
/// to omit [KeyUsage.sign] to prevent the key from being misused to sign new
/// data in another context.
enum KeyUsage {
  /// Key can be used for encrypting data.
  encrypt,

  /// Key can be used for decrypting data.
  decrypt,

  /// Key can be used for signing data.
  sign,

  /// Key can be used for verification of signatures.
  verify,

  /// Key can be used to derive new keys.
  deriveKey,

  /// Key can be used to derive bits.
  deriveBits,

  /// Key can be used to encrypt another key.
  wrapKey,

  /// Key can be used to decrypt another key.
  unwrapKey,
}

/// Common interface for all cryptographic keys.
///
/// Once generated or import a [CryptoKey] is immutable. The [usages] properties
/// determines what operations the key can be used for.
/// The [extractable] bit determines if operations that extract the key material
/// is permitted.
///
/// Methods to generate or import [CryptoKey] subclasses are exposed as static
/// methods on the algorithm specific subclass, e.g. see
/// [HmacSecretKey.generateKey] for generating a random [HmacSecretKey].
abstract class CryptoKey {
  CryptoKey._(); // keep the constructor private.

  /// Determines if operations extracting the key is permitted.
  ///
  /// This property cannot be changed once a key have been created, however, it
  /// can be defined when a key is generated or imported.
  bool get extractable;

  /// List of permitted key usages.
  ///
  /// This property cannot be changed once a key have been created, however, it
  /// can be defined when a key is generated or imported.
  List<KeyUsage> get usages;
}

/// A key-pair as returned from key generation.
abstract class CryptoKeyPair<S, T> {
  CryptoKeyPair._(); // keep the constructor private.

  /// Private key for [publicKey].
  S get privateKey;

  /// Public key matching [privateKey].
  T get publicKey;
}
