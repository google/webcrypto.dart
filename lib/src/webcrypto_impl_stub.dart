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

Future<RSASSA_PKCS1_v1_5PrivateKey> RSASSA_PKCS1_v1_5ImportRawPrivateKey({
  List<int> keyData,
  bool extractable,
  List<KeyUsage> usages,
  HashAlgorithm hash,
}) async {
  throw UnimplementedError('importRawPrivateKey stub');
}

Future<RSASSA_PKCS1_v1_5PublicKey> RSASSA_PKCS1_v1_5ImportPublicKey({
  List<int> keyData,
  bool extractable,
  List<KeyUsage> usages,
  HashAlgorithm hash,
}) async {
  throw UnimplementedError('importRawPublicKey stub');
}

Future<CryptoKeyPair<RSASSA_PKCS1_v1_5PrivateKey, RSASSA_PKCS1_v1_5PublicKey>>
    RSASSA_PKCS1_v15GenerateKey({
  int modulusLength,
  BigInt publicExponent,
  HashAlgorithm hash,
  bool extractable,
  List<KeyUsage> usages,
}) async {
  throw UnimplementedError('generateKey stub');
}
