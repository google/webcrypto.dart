/// Web crypto package provides bindings for web cryptography specificaiton.
library webcrypto;

import 'dart:async';
import 'dart:typed_data';
import 'package:meta/meta.dart';

import 'src/webcrypto_impl_stub.dart'
    if (dart.library.ffi) 'src/webcrypto_impl_ffi.dart'
    if (dart.library.io) 'src/webcrypto_impl_native.dart'
    if (dart.library.html) 'src/webcrypto_impl_browser.dart' as impl;
import 'src/utils.dart' as utils;
import 'src/cryptokey.dart';

export 'src/exceptions.dart';
export 'src/cryptokey.dart';

/// Fill [destination] with cryptographically random values.
///
/// Does not accept a [destination] larger than `65536` bytes, use multiple
/// calls to obtain more random bytes.
///
/// **Example**
/// ```dart
/// import 'dart:convert' show base64;
/// import 'dart:typed_data' show Uint8List;
/// import 'package:webcrypto/webcrypto.dart';
///
/// // Allocated a byte array of 64 bytes.
/// final bytes = Uint8List(64);
///
/// // Fill with random bytes.
/// getRandomValues(bytes);
///
/// // Print base64 encoded random bytes.
/// print(base64.encode(bytes));
/// ```
void getRandomValues(TypedData destination) {
  ArgumentError.checkNotNull(destination, 'destination');
  if (destination.lengthInBytes > 65536) {
    throw ArgumentError.value(destination, 'destination',
        'array of more than 65536 bytes is not allowed');
  }

  impl.getRandomValues(destination);
}

/// A hash algorithm supported by other methods in this package.
///
/// See [digest] for how to compute the hash sum of a byte stream.
enum HashAlgorithm {
  /// SHA-1 as specified in [FIPS PUB 180-4][1].
  ///
  /// **This algorithm is considered weak** and should not be used in new
  /// cryptographic applications.
  ///
  /// [1]: https://doi.org/10.6028/NIST.FIPS.180-4
  sha1,

  /// SHA-256 as specified in [FIPS PUB 180-4][1].
  ///
  /// [1]: https://doi.org/10.6028/NIST.FIPS.180-4
  sha256,

  /// SHA-384 as specified in [FIPS PUB 180-4][1].
  ///
  /// [1]: https://doi.org/10.6028/NIST.FIPS.180-4
  sha384,

  /// SHA-512 as specified in [FIPS PUB 180-4][1].
  ///
  /// [1]: https://doi.org/10.6028/NIST.FIPS.180-4
  sha512,
}

/// Compute a cryptographic hash-sum of [data] stream using [hash].
///
///
///
/// **Example**
/// ```dart
/// import 'dart:convert' show base64, utf8;
/// import 'package:webcrypto/webcrypto.dart';
///
/// // Function that creates a stream of data we can hash.
/// Stream<List<int>> dataStream() async* {
///   yield utf8.encode('hello world');
/// }
///
/// // Hash of the dataStream with sha-256
/// List<int> hash = await digest(
///   hash: HashAlgorithm.sha256,
///   data: dataStream(),
/// );
///
/// // Print the base64 encoded hash
/// print(base64.encode(hash));
/// ```
///
/// This package does not provide a convenient function for hashing a
/// byte array. But as illustrated in the example above this can be achieved by
/// creating a function that wraps the byte array in a byte stream.
Future<List<int>> digest({
  // Note: It's tempting to use positional arguments, but this could cause
  //       problems if future iterations of the Web Cryptography Specification
  //       defines new digest algorithms with additional parameters.
  //       meta-note: I could probably convinced otherwise too.
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

/// Remove duplicate [usages] and sort according to index in enum.
List<KeyUsage> _normalizeUsages(List<KeyUsage> usages) {
  usages = usages.toSet().toList();
  usages.sort((a, b) => a.index.compareTo(b.index));
  return usages;
}

abstract class HmacSecretKey implements CryptoKey {
  static Future<HmacSecretKey> importRawKey({
    @required List<int> keyData,
    @required HashAlgorithm hash,
    @required bool extractable,
    @required List<KeyUsage> usages,
    int length,
  }) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(hash, 'hash');
    ArgumentError.checkNotNull(extractable, 'extractable');
    _checkAllowedUsages('HMAC', usages, [
      KeyUsage.sign,
      KeyUsage.verify,
    ]);
    usages = _normalizeUsages(usages);
    if (length != null && length > keyData.length * 8) {
      ArgumentError.value(
          length, 'length', 'must be less than number of bits in keyData');
    }
    if (length != null && length <= (keyData.length - 1) * 8) {
      ArgumentError.value(
        length,
        'length',
        'must be greater than number of bits in keyData - 8, you can attain '
            'the same effect by removing bytes from keyData',
      );
    }

    return impl.hmacSecret_importRawKey(
      keyData: keyData,
      extractable: extractable,
      usages: usages,
      hash: hash,
      length: length,
    );
  }

  static Future<HmacSecretKey> generateKey({
    @required HashAlgorithm hash,
    @required bool extractable,
    @required List<KeyUsage> usages,
    int length,
  }) {
    ArgumentError.checkNotNull(hash, 'hash');
    ArgumentError.checkNotNull(extractable, 'extractable');
    _checkAllowedUsages('HMAC', usages, [
      KeyUsage.sign,
      KeyUsage.verify,
    ]);
    usages = _normalizeUsages(usages);
    if (length != null && length <= 0) {
      ArgumentError.value(length, 'length', 'must be positive');
    }

    return impl.hmacSecret_generateKey(
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

abstract class RsassaPkcs1V15PrivateKey implements CryptoKey {
  static Future<RsassaPkcs1V15PrivateKey> importPkcs8Key({
    @required List<int> keyData,
    @required bool extractable,
    @required List<KeyUsage> usages,
    @required HashAlgorithm hash,
  }) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(extractable, 'extractable');
    _checkAllowedUsages('RSASSA_PKCS1_v1_5', usages, [KeyUsage.sign]);
    usages = _normalizeUsages(usages);
    ArgumentError.checkNotNull(hash, 'hash');

    return impl.rsassaPkcs1V15PrivateKey_importPkcs8Key(
      keyData: keyData,
      extractable: extractable,
      usages: usages,
      hash: hash,
    );
  }

  static Future<
          CryptoKeyPair<RsassaPkcs1V15PrivateKey, RsassaPkcs1V15PublicKey>>
      generateKey({
    @required int modulusLength,
    @required BigInt publicExponent,
    @required HashAlgorithm hash,
    @required bool extractable,
    @required List<KeyUsage> usages,
  }) {
    ArgumentError.checkNotNull(modulusLength, 'modulusLength');
    ArgumentError.checkNotNull(publicExponent, 'publicExponent');
    ArgumentError.checkNotNull(hash, 'hash');
    ArgumentError.checkNotNull(extractable, 'extractable');
    _checkAllowedUsages('RSASSA_PKCS1_v1_5', usages, [
      KeyUsage.sign,
      KeyUsage.verify,
    ]);
    usages = _normalizeUsages(usages);

    return impl.rsassaPkcs1V15PrivateKey_generateKey(
      modulusLength: modulusLength,
      publicExponent: publicExponent,
      hash: hash,
      extractable: extractable,
      usages: usages,
    );
  }

  Future<List<int>> sign({
    @required Stream<List<int>> data,
  });

  Future<List<int>> exportPkcs8Key();
}

abstract class RsassaPkcs1V15PublicKey implements CryptoKey {
  static Future<RsassaPkcs1V15PublicKey> importSpkiKey({
    @required List<int> keyData,
    @required bool extractable,
    @required List<KeyUsage> usages,
    @required HashAlgorithm hash,
  }) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(extractable, 'extractable');
    _checkAllowedUsages('RSASSA_PKCS1_v1_5', usages, [KeyUsage.verify]);
    usages = _normalizeUsages(usages);
    ArgumentError.checkNotNull(hash, 'hash');

    return impl.rsassaPkcs1V15PublicKey_importSpkiKey(
      keyData: keyData,
      extractable: extractable,
      usages: usages,
      hash: hash,
    );
  }

  Future<bool> verify({
    @required List<int> signature,
    @required Stream<List<int>> data,
  });

  Future<List<int>> exportSpkiKey();
}
