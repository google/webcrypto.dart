import 'dart:typed_data';
import 'package:meta/meta.dart';

import 'src/webcrypto_impl_stub.dart'
    // if (dart.library.io) 'src/webcrypto_impl_native.dart'
    if (dart.library.html) 'src/webcrypto_impl_browser.dart' as impl;
import 'src/utils.dart' as utils;
import 'src/cryptokey.dart';

export 'src/exceptions.dart';
export 'src/cryptokey.dart';

/// Fill [destination] with cryptographically random values.
///
/// Throws [ArgumentError] the size of [destination] is more than `65536`, to
/// extract many bytes simply make repeated calls.
void getRandomValues(TypedData destination) {
  ArgumentError.checkNotNull(destination, 'destination');
  if (destination.lengthInBytes > 65536) {
    throw ArgumentError.value(destination, 'destination',
        'array of more than 65536 bytes is not allowed');
  }

  impl.getRandomValues(destination);
}

enum HashAlgorithm {
  sha1,
  sha256,
  sha384,
  sha512,
}

Future<List<int>> digest({
  @required HashAlgorithm hash,
  @required Stream<List<int>> data,
}) {
  ArgumentError.checkNotNull(hash, 'hash');
  ArgumentError.checkNotNull(data, 'data');

  return impl.digest(hash: hash, data: data);
}

/// Check that [usages] is a subset of [allowedUsages], throws an
/// [ArgumentError] if:
///  * [usages] is `null`
///  * [usages] is not a subset of [allowedUsages].
///
/// The [algorithm] paramter is used specify a string that will be used in the
/// error message explaining why a given usage is not allowed.
void _checkAllowedUsages(
  String algorithm,
  List<KeyUsage> usages,
  List<KeyUsage> allowedUsages,
) {
  ArgumentError.checkNotNull(usages, 'usages');
  for (final usage in usages) {
    if (!allowedUsages.contains(usage)) {
      final allowedList = allowedUsages.map(utils.keyUsageToString).join(', ');
      ArgumentError.value(
          usage, 'usages', '$algorithm only supports usages $allowedList');
    }
  }
}

abstract class HmacSecretKey implements CryptoKey {
  static Future<HmacSecretKey> importRawKey({
    @required List<int> keyData,
    @required bool extractable,
    @required List<KeyUsage> usages,
    @required HashAlgorithm hash,
    int length,
  }) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(extractable, 'extractable');
    _checkAllowedUsages('HMAC', usages, [
      KeyUsage.sign,
      KeyUsage.verify,
    ]);
    return impl.hmacSecretImportRawKey(
      keyData: keyData,
      extractable: extractable,
      usages: usages,
      hash: hash,
      length: length,
    );
  }

  Future<List<int>> sign({
    @required Stream<List<int>> data,
  });

  Future<bool> verify({
    @required List<int> signature,
    @required Stream<List<int>> data,
  });

  Future<List<int>> exportRawKey();
}

/*
abstract class RSASSA_PKCS1_v1_5PrivateKey implements CryptoKey {
  static Future<RSASSA_PKCS1_v1_5PrivateKey> importKey({
    KeyFormat format,
    List<int> keyData,
    bool extractable,
    List<KeyUsage> usages,
  }) =>
      impl.importRSASSA_PKCS1_v1_5PrivateKey(
        format: format,
        keyData: keyData,
        extractable: extractable,
        usages: usages,
      );

  static Future<
      CryptoKeyPair<RSASSA_PKCS1_v1_5PrivateKey,
          RSASSA_PKCS1_v1_5PublicKey>> generateKey({
    int modulusLength,
    List<int> publicExponent,
    HashAlgorithm hash,
  }) =>
      impl.generateRSASSA_PKCS1_v15Key(
        modulusLength: modulusLength,
        publicExponent: publicExponent,
        hash: hash,
      );

  Future<List<int>> sign({Stream<List<int>> data});
}

abstract class RSASSA_PKCS1_v1_5PublicKey implements CryptoKey {
  static Future<RSASSA_PKCS1_v1_5PublicKey> importKey({
    KeyFormat format,
    List<int> keyData,
    bool extractable,
    List<KeyUsage> usages,
  }) =>
      impl.importRSASSA_PKCS1_v1_5PublicKey(
        format: format,
        keyData: keyData,
        extractable: extractable,
        usages: usages,
      );

  Future<bool> verify({List<int> signature, Stream<List<int>> data});
}
*/
