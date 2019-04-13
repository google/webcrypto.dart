import 'dart:async';
import 'dart:typed_data';
import '../webcrypto.dart';
import 'exceptions.dart';
import 'webcrypto_extension/webcrypto_extension.dart' as ext;

final _notImplemented = UnimplementedError(
  'webcrypto not availble on this platform',
);

abstract class _CryptoKeyBase implements CryptoKey {
  final bool extractable;
  final List<KeyUsage> usages;
  _CryptoKeyBase(this.extractable, this.usages) {
    // Verify invariants that should be checked other places.
    assert(extractable != null);
    assert(usages != null);
  }

  void _checkUsage(KeyUsage usage) {
    if (!usages.contains(usage)) {
      String name;
      switch (usage) {
        case KeyUsage.encrypt:
          name = 'encrypt';
          break;
        case KeyUsage.decrypt:
          name = 'decrypt';
          break;
        case KeyUsage.sign:
          name = 'sign';
          break;
        case KeyUsage.verify:
          name = 'verify';
          break;
        // case KeyUsage.deriveKey:
        //   name = 'deriveKey';
        //   break;
        case KeyUsage.deriveBits:
          name = 'deriveBits';
          break;
        // case KeyUsage.wrapKey:
        //   name = 'wrapKey';
        //   break;
        // case KeyUsage.unwrapKey:
        //   name = 'unwrapKey';
        //   break;
      }
      assert(name != null, 'unknown KeyUsage');
      if (name == null) {
        name = 'unknown';
      }
      throw StateError(
        'operation forbidding, the key was not created with `KeyUsage.$name`',
      );
    }
  }

  void _checkExtractable() {
    if (!extractable) {
      throw StateError(
        'key cannot be extracted, when created with `extractable = false`',
      );
    }
  }
}

Uint8List _ensureUint8List(List<int> data) {
  if (data is Uint8List) {
    return data;
  }
  return Uint8List.fromList(data);
}

void _throwOperationExceptionIfString(dynamic value) {
  if (value is String) {
    throw operationException(value);
  }
}

int _hashAlgorithmLength(HashAlgorithm hash) {
  switch (hash) {
    case HashAlgorithm.sha1:
      return 160;
    case HashAlgorithm.sha256:
      return 256;
    case HashAlgorithm.sha384:
      return 384;
    case HashAlgorithm.sha512:
      return 512;
  }
  throw AssertionError('Unknown HashAlgorithm with index: ${hash.index}');
}

//---------------------- Random Bytes

void getRandomValues(TypedData destination) {
  ArgumentError.checkNotNull(destination, 'destination');

  final err = ext.getRandomValues(destination.buffer.asUint8List());
  if (err != null) {
    throw operationException(err);
  }
}

//---------------------- Hash Algorithms

Future<List<int>> digest({HashAlgorithm hash, Stream<List<int>> data}) async {
  ArgumentError.checkNotNull(hash, 'hash');
  ArgumentError.checkNotNull(data, 'data');

  // Create a digest context
  final ctx = ext.digest_create(ext.hashAlgorithmToHashIdentifier(hash));
  if (ctx is String) {
    throw operationException(ctx);
  }

  try {
    // Feed ctx with data
    await for (final chunk in data) {
      final ret = ext.digest_write(ctx, _ensureUint8List(chunk));
      _throwOperationExceptionIfString(ret);
    }

    // Extract the result
    final ret = ext.digest_result(ctx);
    _throwOperationExceptionIfString(ret);
    return ret as Uint8List;
  } finally {
    final ret = ext.digest_destroy(ctx);
    _throwOperationExceptionIfString(ret);
  }
}

//---------------------- HMAC

/// Convert [data] to [Uint8List] and zero to [lengthInBits] if given.
Uint8List _asUint8ListZeroedToBitLength(List<int> data, [int lengthInBits]) {
  data = Uint8List.fromList(data);
  if (lengthInBits != null) {
    final startFrom = (lengthInBits / 8).floor();
    int remainder = (lengthInBits % 8).toInt();
    for (int i = startFrom; i < data.length; i++) {
      // TODO: This passes tests, but I think this should be >> instead.. hmm...
      final mask = 0xff & (0xff << (8 - remainder));
      data[i] = data[i] & mask;
      remainder = 8;
    }
  }
  return data;
}

Future<HmacSecretKey> hmacSecret_importRawKey({
  List<int> keyData,
  bool extractable,
  List<KeyUsage> usages,
  HashAlgorithm hash,
  int length,
}) async {
  return _HmacSecretKey(
    ext.hashAlgorithmToHashIdentifier(hash),
    _asUint8ListZeroedToBitLength(keyData, length),
    extractable,
    usages,
  );
}

Future<HmacSecretKey> hmacSecret_generateKey({
  bool extractable,
  List<KeyUsage> usages,
  HashAlgorithm hash,
  int length,
}) async {
  if (length == null) {
    length = _hashAlgorithmLength(hash);
  }
  final keyData = Uint8List((length / 8).ceil());
  getRandomValues(keyData);

  return _HmacSecretKey(
    ext.hashAlgorithmToHashIdentifier(hash),
    _asUint8ListZeroedToBitLength(keyData, length),
    extractable,
    usages,
  );
}

class _HmacSecretKey extends _CryptoKeyBase implements HmacSecretKey {
  final int _hash;
  final Uint8List _keyData;

  _HmacSecretKey(this._hash, this._keyData, extractable, List<KeyUsage> usages)
      : super(extractable, usages);

  Future<Uint8List> _sign(Stream<List<int>> data) async {
    // Create a context
    final ctx = ext.hmac_create(_hash, _keyData);
    if (ctx is String) {
      throw operationException(ctx);
    }

    try {
      // Feed ctx with data
      await for (final chunk in data) {
        final ret = ext.hmac_write(ctx, _ensureUint8List(chunk));
        _throwOperationExceptionIfString(ret);
      }

      // Extract the result
      final ret = ext.hmac_result(ctx);
      _throwOperationExceptionIfString(ret);
      return ret as Uint8List;
    } finally {
      final ret = ext.hmac_destroy(ctx);
      _throwOperationExceptionIfString(ret);
    }
  }

  @override
  Future<List<int>> sign({Stream<List<int>> data}) async {
    _checkUsage(KeyUsage.sign);

    return await _sign(data);
  }

  @override
  Future<bool> verify({List<int> signature, Stream<List<int>> data}) async {
    _checkUsage(KeyUsage.verify);

    final signature2 = await _sign(data);
    final ret = ext.compare(_ensureUint8List(signature), signature2);
    _throwOperationExceptionIfString(ret);
    return ret as bool;
  }

  @override
  Future<List<int>> exportRawKey() async {
    _checkExtractable();
    return Uint8List.fromList(_keyData);
  }
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
  final keyHandle = Object();

  final ret = ext.rsassa_importSpkiKey(keyHandle, _ensureUint8List(keyData));
  _throwOperationExceptionIfString(ret);

  throw _RsassaPkcs1V15PublicKey(
    keyHandle,
    ext.hashAlgorithmToHashIdentifier(hash),
    extractable,
    usages,
  );
}

class _RsassaPkcs1V15PublicKey extends _CryptoKeyBase
    implements RsassaPkcs1V15PublicKey {
  final Object _keyHandle;
  final int _hash;

  _RsassaPkcs1V15PublicKey(
    this._keyHandle,
    this._hash,
    extractable,
    List<KeyUsage> usages,
  ) : super(extractable, usages);

  @override
  Future<bool> verify({List<int> signature, Stream<List<int>> data}) {
    return null;
  }

  @override
  Future<List<int>> exportSpkiKey() {
    return null;
  }
}

/*
class _RsassaPkcs1V15PrivateKey extends _BrowserCryptoKeyBase
    implements RsassaPkcs1V15PrivateKey {
  _RsassaPkcs1V15PrivateKey(subtle.CryptoKey key) : super(key);

  @override
  Future<List<int>> sign({Stream<List<int>> data}) {
    return _sign(_rsassaPkcs1V15Algorithm, _key, data);
  }

  @override
  Future<List<int>> exportPkcs8Key() {
    return _exportKey('pkcs8', _key);
  }
}
*/
