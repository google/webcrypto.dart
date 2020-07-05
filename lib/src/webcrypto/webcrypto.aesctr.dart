part of webcrypto;

@sealed
abstract class AesCtrSecretKey {
  AesCtrSecretKey._(); // keep the constructor private.

  static Future<AesCtrSecretKey> importRawKey(List<int> keyData) {
    ArgumentError.checkNotNull(keyData, 'keyData');

    return impl.aesCtr_importRawKey(keyData);
  }

  static Future<AesCtrSecretKey> importJsonWebKey(Map<String, dynamic> jwk) {
    ArgumentError.checkNotNull(jwk, 'jwk');

    return impl.aesCtr_importJsonWebKey(jwk);
  }

  static Future<AesCtrSecretKey> generateKey(int length) {
    ArgumentError.checkNotNull(length, 'length');

    return impl.aesCtr_generateKey(length);
  }

  // Note. that if counter wraps around, then this is broken on Firefox.
  Future<Uint8List> encryptBytes(
    List<int> data,
    List<int> counter,
    int length,
  );

  Stream<Uint8List> encryptStream(
    Stream<List<int>> data,
    List<int> counter,
    int length,
  );

  Future<Uint8List> decryptBytes(
    List<int> data,
    List<int> counter,
    int length,
  );

  Stream<Uint8List> decryptStream(
    Stream<List<int>> data,
    List<int> counter,
    int length,
  );

  Future<Uint8List> exportRawKey();

  Future<Map<String, dynamic>> exportJsonWebKey();
}
