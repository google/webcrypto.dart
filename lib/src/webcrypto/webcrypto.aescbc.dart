part of webcrypto;

@sealed
abstract class AesCbcSecretKey {
  AesCbcSecretKey._(); // keep the constructor private.

  static Future<AesCbcSecretKey> importRawKey(List<int> keyData) {
    ArgumentError.checkNotNull(keyData, 'keyData');

    return impl.aesCbc_importRawKey(keyData);
  }

  static Future<AesCbcSecretKey> importJsonWebKey(Map<String, dynamic> jwk) {
    ArgumentError.checkNotNull(jwk, 'jwk');

    return impl.aesCbc_importJsonWebKey(jwk);
  }

  static Future<AesCbcSecretKey> generateKey(int length) {
    ArgumentError.checkNotNull(length, 'length');

    return impl.aesCbc_generateKey(length);
  }

  Future<Uint8List> encryptBytes(List<int> data, List<int> iv);

  Stream<Uint8List> encryptStream(Stream<List<int>> data, List<int> iv);

  Future<Uint8List> decryptBytes(List<int> data, List<int> iv);

  Stream<Uint8List> decryptStream(Stream<List<int>> data, List<int> iv);

  Future<Uint8List> exportRawKey();

  Future<Map<String, dynamic>> exportJsonWebKey();
}
