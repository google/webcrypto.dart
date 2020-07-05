part of webcrypto;

@sealed
abstract class RsaPssPrivateKey {
  RsaPssPrivateKey._(); // keep the constructor private.

  static Future<RsaPssPrivateKey> importPkcs8Key(
    List<int> keyData,
    Hash hash,
  ) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(hash, 'hash');

    return impl.rsaPssPrivateKey_importPkcs8Key(keyData, hash);
  }

  static Future<RsaPssPrivateKey> importJsonWebKey(
    Map<String, dynamic> jwk,
    Hash hash,
  ) {
    ArgumentError.checkNotNull(jwk, 'jwk');
    ArgumentError.checkNotNull(hash, 'hash');

    return impl.rsaPssPrivateKey_importJsonWebKey(jwk, hash);
  }

  static Future<KeyPair<RsaPssPrivateKey, RsaPssPublicKey>> generateKey(
    int modulusLength,
    BigInt publicExponent,
    Hash hash,
  ) {
    ArgumentError.checkNotNull(modulusLength, 'modulusLength');
    ArgumentError.checkNotNull(publicExponent, 'publicExponent');
    ArgumentError.checkNotNull(hash, 'hash');

    return impl.rsaPssPrivateKey_generateKey(
      modulusLength,
      publicExponent,
      hash,
    );
  }

  Future<Uint8List> signBytes(List<int> data, int saltLength);
  Future<Uint8List> signStream(Stream<List<int>> data, int saltLength);

  Future<Uint8List> exportPkcs8Key();

  Future<Map<String, dynamic>> exportJsonWebKey();
}

@sealed
abstract class RsaPssPublicKey {
  RsaPssPublicKey._(); // keep the constructor private.

  static Future<RsaPssPublicKey> importSpkiKey(
    List<int> keyData,
    Hash hash,
  ) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(hash, 'hash');

    return impl.rsaPssPublicKey_importSpkiKey(keyData, hash);
  }

  static Future<RsaPssPublicKey> importJsonWebKey(
    Map<String, dynamic> jwk,
    Hash hash,
  ) {
    ArgumentError.checkNotNull(jwk, 'jwk');
    ArgumentError.checkNotNull(hash, 'hash');

    return impl.rsaPssPublicKey_importJsonWebKey(jwk, hash);
  }

  Future<bool> verifyBytes(
    List<int> signature,
    List<int> data,
    int saltLength,
  );

  Future<bool> verifyStream(
    List<int> signature,
    Stream<List<int>> data,
    int saltLength,
  );

  Future<Uint8List> exportSpkiKey();

  Future<Map<String, dynamic>> exportJsonWebKey();
}
