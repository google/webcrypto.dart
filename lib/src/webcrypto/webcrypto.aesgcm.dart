part of webcrypto;

@sealed
abstract class AesGcmSecretKey {
  AesGcmSecretKey._(); // keep the constructor private.

  static Future<AesGcmSecretKey> importRawKey(List<int> keyData) {
    ArgumentError.checkNotNull(keyData, 'keyData');

    return impl.aesGcm_importRawKey(keyData);
  }

  static Future<AesGcmSecretKey> importJsonWebKey(Map<String, dynamic> jwk) {
    ArgumentError.checkNotNull(jwk, 'jwk');

    return impl.aesGcm_importJsonWebKey(jwk);
  }

  static Future<AesGcmSecretKey> generateKey(int length) {
    ArgumentError.checkNotNull(length, 'length');

    return impl.aesGcm_generateKey(length);
  }

  // TODO: Document that this does not provide a streaming interface because
  //       access to the decrypted bytes before verification of the
  //       authentication tag defeats the purpose of authenticated-encryption.
  Future<Uint8List> encryptBytes(
    List<int> data,
    List<int> iv, {
    List<int> additionalData,
    int tagLength = 128,
  });

  Future<Uint8List> decryptBytes(
    List<int> data,
    List<int> iv, {
    List<int> additionalData,
    int tagLength = 128,
  });

  Future<Uint8List> exportRawKey();

  Future<Map<String, dynamic>> exportJsonWebKey();
}
