part of 'impl_interface.dart';

abstract interface class StaticAesCbcSecretKeyImpl {
  Future<AesCbcSecretKeyImpl> importRawKey(List<int> keyData);
  Future<AesCbcSecretKeyImpl> importJsonWebKey(Map<String, dynamic> jwk);
  Future<AesCbcSecretKeyImpl> generateKey(int length);
}

abstract class AesCbcSecretKeyImpl {
  Future<Uint8List> encryptBytes(List<int> data, List<int> iv);
  Future<Uint8List> decryptBytes(List<int> data, List<int> iv);
  Stream<Uint8List> encryptStream(Stream<List<int>> data, List<int> iv);
  Stream<Uint8List> decryptStream(Stream<List<int>> data, List<int> iv);
  Future<Uint8List> exportRawKey();
  Future<Map<String, dynamic>> exportJsonWebKey();
}
