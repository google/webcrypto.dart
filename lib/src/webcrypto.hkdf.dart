part of webcrypto;

@sealed
abstract class HkdfSecretKey {
  HkdfSecretKey._(); // keep the constructor private.

  static Future<HkdfSecretKey> importRawKey(List<int> keyData) {
    ArgumentError.checkNotNull(keyData, 'keyData');

    return impl.hkdfSecretKey_importRawKey(keyData);
  }

  Future<Uint8List> deriveBits(
    int length,
    Hash hash,
    List<int> salt,
    List<int> info,
  );
}
