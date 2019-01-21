import '../webcrypto.dart';
import 'crypto_subtle.dart' as subtle;
import 'utils.dart' as utils;
import 'dart:typed_data';
import 'dart:html' show DomException;

void _throwAsErrorOrException(DomException e) {
  switch (e.name) {
    case 'NotSupportedError':
      throw NotSupportedException(e.message);
    case 'SyntaxError':
      // SyntaxError is thrown as ArgumentError
      throw ArgumentError(e.message);
    case 'InvalidAccessError':
      // InvalidAccessError is thrown as StateError
      throw StateError(e.message);
    case 'DataError':
      throw DataException(e.message);
    case 'OperationError':
      throw OperationException(e.message);
    case 'QuotaExceededError':
      throw ArgumentError(e.message);
  }
  throw AssertionError('Unexpected exception from web cryptography'
      '"${e.name}", message: ${e.message}');
}

/// Handle instances of [subtle.DomException] specified in the
/// [Web Cryptograpy specification][1].
///
/// [1]: https://www.w3.org/TR/WebCryptoAPI/#SubtleCrypto-Exceptions
Future<T> _catchDomException<T>(Future<T> Function() fn) async {
  try {
    return await fn();
  } on DomException catch (e) {
    _throwAsErrorOrException(e);
  }
}

/// BaseClass for [CryptoKey] subclasses wrapping a [subtle.CryptoKey].
abstract class _BrowserCryptoKeyBase implements CryptoKey {
  /// CryptoKey object being wrapped.
  final subtle.CryptoKey _key;

  _BrowserCryptoKeyBase(this._key);

  @override
  bool get extractable => _key.extractable;

  @override
  List<KeyUsage> get usages => subtle.stringsToKeyUsages(_key.usages);
}

///////////////////////////// Wrappers

/// Adapt `crypto.subtle.importKey` to dart types.
Future<subtle.CryptoKey> _importKey(
  String format,
  List<int> keyData,
  subtle.Algorithm algorithm,
  bool extractable,
  List<KeyUsage> usages,
) {
  return _catchDomException(() async {
    return subtle.promiseAsFuture(subtle.importKey(
      format,
      Uint8List.fromList(keyData),
      algorithm,
      extractable,
      subtle.keyUsagesToStrings(usages),
    ));
  });
}

/// Adapt `crypto.subtle.sign` to dart types.
Future<List<int>> _sign(
  subtle.Algorithm algorithm,
  subtle.CryptoKey key,
  Stream<List<int>> data,
) {
  ArgumentError.checkNotNull(data, 'data');

  return _catchDomException(() async {
    final result = await subtle.promiseAsFuture(subtle.sign(
      algorithm,
      key,
      await utils.asBuffer(data),
    ));
    return result.asUint8List();
  });
}

/// Adapt `crypto.subtle.verify` to dart types.
Future<bool> _verify(
  subtle.Algorithm algorithm,
  subtle.CryptoKey key,
  List<int> signature,
  Stream<List<int>> data,
) {
  ArgumentError.checkNotNull(signature, 'signature');
  ArgumentError.checkNotNull(data, 'data');

  return _catchDomException(() async {
    return await subtle.promiseAsFuture(subtle.verify(
      algorithm,
      key,
      Uint8List.fromList(signature),
      await utils.asBuffer(data),
    ));
  });
}

/// Adapt `crypto.subtle.export` to dart types.
Future<List<int>> _exportKey(
  String format,
  subtle.CryptoKey key,
) {
  ArgumentError.checkNotNull(format, 'format');

  return _catchDomException(() async {
    final result = await subtle.promiseAsFuture(subtle.exportKey(format, key));
    return result.asUint8List();
  });
}

///////////////////////////// Random Bytes

void getRandomValues(TypedData destination) {
  try {
    subtle.getRandomValues(destination);
  } on DomException catch (e) {
    _throwAsErrorOrException(e);
  }
}

///////////////////////////// HashAlgorithms

/// Wrap `crypto.subtle.digest`.
Future<List<int>> digest({HashAlgorithm hash, Stream<List<int>> data}) {
  return _catchDomException(() async {
    final algorithm = subtle.hashAlgorithmToString(hash);
    final input = await utils.asBuffer(data);

    final result = await subtle.promiseAsFuture(subtle.digest(
      algorithm,
      input,
    ));
    return result.asUint8List();
  });
}

///////////////////////////// HMAC

/// Wrap `crypto.subtle.importKey` for use in importing keys with the `HMAC`
/// algorithm, and return the result wrapped as [HmacSecretKey].
Future<HmacSecretKey> hmacSecretImportRawKey({
  List<int> keyData,
  bool extractable,
  List<KeyUsage> usages,
  HashAlgorithm hash,
  int length,
}) async {
  // Construct object with algorithm specific options
  final algorithm = subtle.Algorithm(
    name: 'HMAC',
    hash: subtle.hashAlgorithmToString(hash),
    //length: length, //TODO: try with this again!!!!
  );

  final k = await _importKey('raw', keyData, algorithm, extractable, usages);
  assert(k.type == 'secret', 'expected a "secret" key');
  return _HmacSecretKey(k);
}

final _hmacAlgorithm = subtle.Algorithm(name: 'HMAC');

class _HmacSecretKey extends _BrowserCryptoKeyBase implements HmacSecretKey {
  _HmacSecretKey(subtle.CryptoKey key) : super(key);

  @override
  Future<List<int>> sign({Stream<List<int>> data}) {
    return _sign(_hmacAlgorithm, _key, data);
  }

  @override
  Future<bool> verify({List<int> signature, Stream<List<int>> data}) {
    return _verify(_hmacAlgorithm, _key, signature, data);
  }

  @override
  Future<List<int>> exportRawKey() {
    return _exportKey('raw', _key);
  }
}

///////////////////////////// RSASSA_PKCS1_v1_5
