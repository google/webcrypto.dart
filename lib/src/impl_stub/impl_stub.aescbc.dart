part of 'impl_stub.dart';

abstract class AesCbcSecretKeyImpl {
  static Future<AesCbcSecretKeyImpl> importRawKey(List<int> keyData) {
    return impl.aesCbc_importRawKey(keyData);
  }

  static Future<AesCbcSecretKeyImpl> importJsonWebKey(Map<String, dynamic> jwk) {
    return impl.aesCbc_importJsonWebKey(jwk);
  }

  static Future<AesCbcSecretKeyImpl> generateKey(int length) {
    return impl.aesCbc_generateKey(length);
  }

  Future<Uint8List> encryptBytes(List<int> data, List<int> iv);
  Future<Uint8List> decryptBytes(List<int> data, List<int> iv);
  Stream<Uint8List> encryptStream(Stream<List<int>> data, List<int> iv);
  Stream<Uint8List> decryptStream(Stream<List<int>> data, List<int> iv);
  Future<Uint8List> exportRawKey();
  Future<Map<String, dynamic>> exportJsonWebKey();
}
