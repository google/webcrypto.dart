import 'dart:async';
import 'dart:typed_data';
import '../webcrypto.dart';
import 'webcrypto_extension/webcrypto_extension.dart' as ext;

final _notImplemented = UnimplementedError(
  'webcrypto not availble on this platform',
);

///////////////////////////// Random Bytes

void getRandomValues(TypedData destination) {
  ArgumentError.checkNotNull(destination, 'destination');

  final err = ext.getRandomValues(destination.buffer.asUint8List());
  if (err != null) {
    throw OperationException(err);
  }
}

///////////////////////////// Hash Algorithms

Future<List<int>> digest({HashAlgorithm hash, Stream<List<int>> data}) async {
  ArgumentError.checkNotNull(hash, 'hash');
  ArgumentError.checkNotNull(data, 'data');

  // Create a digest context
  final ctx = ext.digest_create(ext.hashAlgorithmToHashIdentifier(hash));
  if (ctx is String) {
    throw OperationException(ctx);
  }

  try {
    // Feed ctx with data
    await for (var chunk in data) {
      if (!(chunk is Uint8List)) {
        chunk = Uint8List.fromList(chunk);
      }
      final ret = ext.digest_write(ctx, chunk);
      if (ret is String) {
        throw OperationException(ctx);
      }
    }

    // Extract the result
    final ret = ext.digest_result(ctx);
    if (ret is String) {
      throw OperationException(ret);
    }
    return ret as Uint8List;
  } finally {
    final ret = ext.digest_destroy(ctx);
    if (ret is String) {
      throw OperationException(ctx);
    }
  }
}

///////////////////////////// HMAC

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

///////////////////////////// RSASSA_PKCS1_v1_5

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
