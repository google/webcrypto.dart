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

abstract class CryptoKey {
  bool get extractable;
  List<KeyUsage> get usages;
}

abstract class CryptoKeyPair<S, T> {
  S get privateKey;
  T get publicKey;
}
