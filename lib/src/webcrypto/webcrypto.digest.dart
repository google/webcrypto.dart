// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

part of 'webcrypto.dart';

/// A cryptographic hash algorithm implementation.
///
/// The `package:webcrypto/webcrypto.dart` library provides the following implementations of this
/// class:
///  * [Hash.sha1], (this is considered weak, only included for compatibility),
///  * [Hash.sha256],
///  * [Hash.sha384], and,
///  * [Hash.sha512].
///
/// For a guidance on choice of hash function see
/// [NIST SP 800-57 Part 1 Rev 5][1].
///
/// Notice custom implementations of this class cannot be passed to
/// to other methods in this library.
///
/// [1]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
abstract final class Hash {
  HashImpl get _impl;

  const Hash._(); // keep the constructor private.

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
  Future<Uint8List> digestBytes(List<int> data) => _impl.digestBytes(data);

  /// Compute a cryptographic hash-sum of [data] stream using this [Hash].
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:io' show File;
  /// import 'dart:convert' show base64;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// Future<void> main() async {
  ///   // Pick a file to hash.
  ///   final fileToHash = File('example.txt');
  ///   await fileToHash.writeAsString('hello world');
  ///
  ///   // Compute hash of fileToHash with sha-256
  ///   List<int> hash;
  ///   final stream = fileToHash.openRead();
  ///   try {
  ///     hash = await Hash.sha256.digestStream(stream);
  ///   } finally {
  ///     await stream.close(); // always close the stream
  ///   }
  ///
  ///   // Print the base64 encoded hash
  ///   print(base64.encode(hash));
  /// }
  /// ```
  Future<Uint8List> digestStream(Stream<List<int>> data) =>
      _impl.digestStream(data);

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
  /// Future<void> main() async {
  ///   // Convert 'hello world' to a byte array
  ///   final bytesToHash = utf8.encode('hello world');
  ///
  ///   // Compute hash of bytesToHash with sha-256
  ///   List<int> hash = await Hash.sha256.digestBytes(bytesToHash);
  ///
  ///   // Print the base64 encoded hash
  ///   print(base64.encode(hash));
  /// }
  /// ```
  ///
  /// [1]: https://doi.org/10.6028/NIST.FIPS.180-4
  static const Hash sha1 = _Sha1();

  /// SHA-256 as specified in [FIPS PUB 180-4][1].
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show base64, utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// Future<void> main() async {
  ///   // Convert 'hello world' to a byte array
  ///   final bytesToHash = utf8.encode('hello world');
  ///
  ///   // Compute hash of bytesToHash with sha-256
  ///   List<int> hash = await Hash.sha256.digestBytes(bytesToHash);
  ///
  ///   // Print the base64 encoded hash
  ///   print(base64.encode(hash));
  /// }
  /// ```
  ///
  /// [1]: https://doi.org/10.6028/NIST.FIPS.180-4
  static const Hash sha256 = _Sha256();

  /// SHA-384 as specified in [FIPS PUB 180-4][1].
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show base64, utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// Future<void> main() async {
  ///   // Convert 'hello world' to a byte array
  ///   final bytesToHash = utf8.encode('hello world');
  ///
  ///   // Compute hash of bytesToHash with sha-384
  ///   List<int> hash = await Hash.sha384.digestBytes(bytesToHash);
  ///
  ///   // Print the base64 encoded hash
  ///   print(base64.encode(hash));
  /// }
  /// ```
  ///
  /// [1]: https://doi.org/10.6028/NIST.FIPS.180-4
  static const Hash sha384 = _Sha384();

  /// SHA-512 as specified in [FIPS PUB 180-4][1].
  ///
  /// **Example**
  /// ```dart
  /// import 'dart:convert' show base64, utf8;
  /// import 'package:webcrypto/webcrypto.dart';
  ///
  /// Future<void> main() async {
  ///   // Convert 'hello world' to a byte array
  ///   final bytesToHash = utf8.encode('hello world');
  ///
  ///   // Compute hash of bytesToHash with sha-512
  ///   List<int> hash = await Hash.sha512.digestBytes(bytesToHash);
  ///
  ///   // Print the base64 encoded hash
  ///   print(base64.encode(hash));
  /// }
  /// ```
  ///
  /// [1]: https://doi.org/10.6028/NIST.FIPS.180-4
  static const Hash sha512 = _Sha512();
}

final class _Sha1 extends Hash {
  const _Sha1() : super._();

  @override
  HashImpl get _impl => webCryptImpl.sha1;
}

final class _Sha256 extends Hash {
  const _Sha256() : super._();

  @override
  HashImpl get _impl => webCryptImpl.sha256;
}

final class _Sha384 extends Hash {
  const _Sha384() : super._();

  @override
  HashImpl get _impl => webCryptImpl.sha384;
}

final class _Sha512 extends Hash {
  const _Sha512() : super._();

  @override
  HashImpl get _impl => webCryptImpl.sha512;
}
