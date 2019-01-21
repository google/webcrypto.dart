import 'dart:typed_data';
import '../webcrypto.dart';

///////////////////////////// Random Bytes

void getRandomValues(TypedData destination) {
  throw UnimplementedError('getRandomValues stub');
}

///////////////////////////// Hash Algorithms

Future<List<int>> digest({HashAlgorithm hash, Stream<List<int>> data}) =>
    throw UnimplementedError('digest stub');

///////////////////////////// HMAC

Future<HmacSecretKey> hmacSecretImportRawKey({
  List<int> keyData,
  bool extractable,
  List<KeyUsage> usages,
  HashAlgorithm hash,
  int length,
}) async {
  throw UnimplementedError('importRawKey stub');
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
