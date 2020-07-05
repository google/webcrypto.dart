part of webcrypto;

@sealed
abstract class Pbkdf2SecretKey {
  Pbkdf2SecretKey._(); // keep the constructor private.

  static Future<Pbkdf2SecretKey> importRawKey(List<int> keyData) {
    ArgumentError.checkNotNull(keyData, 'keyData');

    return impl.pbkdf2SecretKey_importRawKey(keyData);
  }

  Future<Uint8List> deriveBits(
    int length,
    Hash hash,
    List<int> salt,
    int iterations,
  );
}
