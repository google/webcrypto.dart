import 'dart:typed_data';
import '../webcrypto.dart';

final _notImplemented = UnimplementedError(
  'webcrypto not availble on this platform',
);

//---------------------- Random Bytes

void getRandomValues(TypedData destination) {
  throw _notImplemented;
}

//---------------------- Hash Algorithms

Future<List<int>> digest({HashAlgorithm hash, Stream<List<int>> data}) =>
    throw _notImplemented;

//---------------------- HMAC

Future<HmacSecretKey> hmacSecret_importJsonWebKey({
  Map<String, Object> jwk,
  bool extractable,
  List<KeyUsage> usages,
  HashAlgorithm hash,
  int length,
}) async {
  throw _notImplemented;
}

Future<HmacSecretKey> hmacSecret_importRawKey({
  List<int> keyData,
  bool extractable,
  List<KeyUsage> usages,
  HashAlgorithm hash,
  int length,
}) async {
  throw _notImplemented;
}

Future<HmacSecretKey> hmacSecret_generateKey({
  bool extractable,
  List<KeyUsage> usages,
  HashAlgorithm hash,
  int length,
}) async {
  throw _notImplemented;
}

//---------------------- RSASSA_PKCS1_v1_5

Future<RsassaPkcs1V15PrivateKey> rsassaPkcs1V15PrivateKey_importPkcs8Key({
  List<int> keyData,
  bool extractable,
  List<KeyUsage> usages,
  HashAlgorithm hash,
}) async {
  throw _notImplemented;
}

Future<CryptoKeyPair<RsassaPkcs1V15PrivateKey, RsassaPkcs1V15PublicKey>>
    rsassaPkcs1V15PrivateKey_generateKey({
  int modulusLength,
  BigInt publicExponent,
  HashAlgorithm hash,
  bool extractable,
  List<KeyUsage> usages,
}) async {
  throw _notImplemented;
}

Future<RsassaPkcs1V15PublicKey> rsassaPkcs1V15PublicKey_importSpkiKey({
  List<int> keyData,
  bool extractable,
  List<KeyUsage> usages,
  HashAlgorithm hash,
}) async {
  throw _notImplemented;
}
