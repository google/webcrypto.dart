enum KeyUsage {
  encrypt,
  decrypt,
  sign,
  verify,
  deriveKey,
  deriveBits,
  wrapKey,
  unwrapKey,
}

// TODO: Consider making a separate method for each import format, JWK is an object...
enum KeyFormat {
  raw,
  pkcs8,
  spki,
  jwk,
}

abstract class CryptoKey {
  bool get extractable;
  List<KeyUsage> get usages;
}

abstract class CryptoKeyPair<S, T> {
  S get privateKey;
  T get publicKey;
}
