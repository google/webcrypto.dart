import '../webcrypto.dart';

///////////////////////////// Hash Algorithms

Future<List<int>> digest({HashAlgorithm hash, Stream<List<int>> data}) => null;

///////////////////////////// HMAC

Future<HmacSecretKey> importHmacSecretKey({
  KeyFormat format,
  List<int> keyData,
  bool extractable,
  List<KeyUsage> usages,
  HashAlgorithm hash,
  int length,
}) async {
  return _HmacSecretKey();
}

class _HmacSecretKey implements HmacSecretKey {
  @override
  Future<List<int>> sign({Stream<List<int>> data}) => null;

  @override
  Future<bool> verify({List<int> signature, Stream<List<int>> data}) => null;

  @override
  Future<List<int>> export({KeyFormat format}) => null;

  @override
  bool get extractable => null;

  @override
  List<KeyUsage> get usages => null;
}

///////////////////////////// RSASSA_PKCS1_v1_5

/*
Future<RSASSA_PKCS1_v1_5PublicKey> importRSASSA_PKCS1_v1_5PublicKey({
  KeyFormat format,
  List<int> keyData,
  bool extractable,
  List<KeyUsage> usages,
}) async {
  return _RSASSA_PKCS1_v1_5PublicKey();
}

Future<RSASSA_PKCS1_v1_5PrivateKey> importRSASSA_PKCS1_v1_5PrivateKey({
  KeyFormat format,
  List<int> keyData,
  bool extractable,
  List<KeyUsage> usages,
}) async {
  return _RSASSA_PKCS1_v1_5PrivateKey();
}

Future<CryptoKeyPair<RSASSA_PKCS1_v1_5PrivateKey, RSASSA_PKCS1_v1_5PublicKey>>
    generateRSASSA_PKCS1_v15Key({
  int modulusLength,
  List<int> publicExponent,
  HashAlgorithm hash,
}) async {
  return _CryptoKeyPair(
    _RSASSA_PKCS1_v1_5PrivateKey(),
    _RSASSA_PKCS1_v1_5PublicKey(),
  );
}

class _CryptoKeyPair<S, T> implements CryptoKeyPair<S, T> {
  final S privateKey;
  final T publicKey;
  _CryptoKeyPair(this.privateKey, this.publicKey);
}

class _RSASSA_PKCS1_v1_5PrivateKey implements RSASSA_PKCS1_v1_5PrivateKey {
  @override
  Future<List<int>> sign({Stream<List<int>> data}) => null;

  @override
  bool get extractable => null;

  @override
  List<KeyUsage> get usages => null;
}

class _RSASSA_PKCS1_v1_5PublicKey implements RSASSA_PKCS1_v1_5PublicKey {
  @override
  Future<bool> verify({List<int> signature, Stream<List<int>> data}) => null;

  @override
  bool get extractable => null;

  @override
  List<KeyUsage> get usages => null;
}
*/
