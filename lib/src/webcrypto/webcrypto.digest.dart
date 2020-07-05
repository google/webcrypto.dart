part of webcrypto;

/// A cryptographic hash algorithm implementation.
///
/// The `package:webcrypto/webcrypto.dart` library provides the following implementations of this
/// class:
///  * [Hash.sha1], (this is considered weak, only included for compatibility),
///  * [Hash.sha256],
///  * [Hash.sha384], and,
///  * [Hash.sha512].
///
/// **WARNING:** Custom implementations of this class cannot be passed to
/// to other methods in this library.
@sealed
abstract class Hash {
  Hash._(); // keep the constructor private.

  /// Compute a cryptographic hash-sum of [data] using this [Hash].
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show base64, utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Convert 'hello world' to a byte array
  /// final bytesToHash = utf8.encode('hello world');
  ///
  /// // Compute hash of bytesToHash with sha-256
  /// List<int> hash = await Hash.sha256.digestBytes(bytesToHash);
  ///
  /// // Print the base64 encoded hash
  /// print(base64.encode(hash));
  /// ```
  Future<Uint8List> digestBytes(List<int> data);

  /// Compute a cryptographic hash-sum of [data] stream using this [Hash].
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:io' show File;
  /// import 'dart:convert' show base64;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Pick a file to hash.
  /// String fileToHash = '/etc/passwd';
  ///
  /// // Compute hash of fileToHash with sha-256
  /// List<int> hash;
  /// final stream = File(fileToHash).openRead();
  /// try {
  ///   hash = await Hash.sha256.digestStream(stream);
  /// } finally {
  ///   await stream.close(); // always close the stream
  /// }
  ///
  /// // Print the base64 encoded hash
  /// print(base64.encode(hash));
  /// ```
  Future<Uint8List> digestStream(Stream<List<int>> data);

  /// SHA-1 as specified in [FIPS PUB 180-4][1].
  ///
  /// **This algorithm is considered weak** and should not be used in new
  /// cryptographic applications.
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show base64, utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Convert 'hello world' to a byte array
  /// final bytesToHash = utf8.encode('hello world');
  ///
  /// // Compute hash of bytesToHash with sha-256
  /// List<int> hash = await Hash.sha256.digestBytes(bytesToHash);
  ///
  /// // Print the base64 encoded hash
  /// print(base64.encode(hash));
  /// ```
  ///
  /// [1]: https://doi.org/10.6028/NIST.FIPS.180-4
  static const Hash sha1 = impl.sha1;

  /// SHA-256 as specified in [FIPS PUB 180-4][1].
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show base64, utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Convert 'hello world' to a byte array
  /// final bytesToHash = utf8.encode('hello world');
  ///
  /// // Compute hash of bytesToHash with sha-256
  /// List<int> hash = await Hash.sha256.digestBytes(bytesToHash);
  ///
  /// // Print the base64 encoded hash
  /// print(base64.encode(hash));
  /// ```
  ///
  /// [1]: https://doi.org/10.6028/NIST.FIPS.180-4
  static const Hash sha256 = impl.sha256;

  /// SHA-384 as specified in [FIPS PUB 180-4][1].
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show base64, utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Convert 'hello world' to a byte array
  /// final bytesToHash = utf8.encode('hello world');
  ///
  /// // Compute hash of bytesToHash with sha-384
  /// List<int> hash = await Hash.sha384.digestBytes(bytesToHash);
  ///
  /// // Print the base64 encoded hash
  /// print(base64.encode(hash));
  /// ```
  ///
  /// [1]: https://doi.org/10.6028/NIST.FIPS.180-4
  static const Hash sha384 = impl.sha384;

  /// SHA-512 as specified in [FIPS PUB 180-4][1].
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show base64, utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// // Convert 'hello world' to a byte array
  /// final bytesToHash = utf8.encode('hello world');
  ///
  /// // Compute hash of bytesToHash with sha-512
  /// List<int> hash = await Hash.sha512.digestBytes(bytesToHash);
  ///
  /// // Print the base64 encoded hash
  /// print(base64.encode(hash));
  /// ```
  ///
  /// [1]: https://doi.org/10.6028/NIST.FIPS.180-4
  static const Hash sha512 = impl.sha512;
}
