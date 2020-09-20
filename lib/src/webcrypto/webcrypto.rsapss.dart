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

part of webcrypto;

@sealed
abstract class RsaPssPrivateKey {
  RsaPssPrivateKey._(); // keep the constructor private.

  static Future<RsaPssPrivateKey> importPkcs8Key(
    List<int> keyData,
    Hash hash,
  ) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(hash, 'hash');

    return impl.rsaPssPrivateKey_importPkcs8Key(keyData, hash);
  }

  static Future<RsaPssPrivateKey> importJsonWebKey(
    Map<String, dynamic> jwk,
    Hash hash,
  ) {
    ArgumentError.checkNotNull(jwk, 'jwk');
    ArgumentError.checkNotNull(hash, 'hash');

    return impl.rsaPssPrivateKey_importJsonWebKey(jwk, hash);
  }

  static Future<KeyPair<RsaPssPrivateKey, RsaPssPublicKey>> generateKey(
    int modulusLength,
    BigInt publicExponent,
    Hash hash,
  ) {
    ArgumentError.checkNotNull(modulusLength, 'modulusLength');
    ArgumentError.checkNotNull(publicExponent, 'publicExponent');
    ArgumentError.checkNotNull(hash, 'hash');

    return impl.rsaPssPrivateKey_generateKey(
      modulusLength,
      publicExponent,
      hash,
    );
  }

  ///
  ///
  /// ## Notes on saltLength
  /// [saltLength] is given in number of bytes.
  ///
  /// [WebKit on mac][1] uses [CommonCrypto][2] which uses [corecrypto][3] which
  /// follows [FIPS 186-4, Section 5.5, Step (e)][4] restricting [saltLength] to
  /// `0 <= saltLength <= hashLength`.
  ///
  /// TODO: Make a recommendation for the following:
  /// [RFC 3447][5] notes that typical [saltLength] is 0 or _length of hash_.
  /// For more information see [RFC 3447 Section 9.1, Notes 4][6].
  ///
  /// [1]: https://trac.webkit.org/browser/webkit/trunk/Source/WebCore/crypto/mac/CryptoAlgorithmRSA_PSSMac.cpp?rev=238754#L56
  /// [2]: https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60165.120.1/lib/CommonRSACryptor.c.auto.html
  /// [3]: https://opensource.apple.com/source/xnu/xnu-4570.41.2/EXTERNAL_HEADERS/corecrypto/ccrsa.h.auto.html
  /// [4]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
  /// [5]: https://tools.ietf.org/html/rfc3447
  /// [6]: https://tools.ietf.org/html/rfc3447#section-9.1
  Future<Uint8List> signBytes(List<int> data, int saltLength);
  Future<Uint8List> signStream(Stream<List<int>> data, int saltLength);

  Future<Uint8List> exportPkcs8Key();

  Future<Map<String, dynamic>> exportJsonWebKey();
}

@sealed
abstract class RsaPssPublicKey {
  RsaPssPublicKey._(); // keep the constructor private.

  static Future<RsaPssPublicKey> importSpkiKey(
    List<int> keyData,
    Hash hash,
  ) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(hash, 'hash');

    return impl.rsaPssPublicKey_importSpkiKey(keyData, hash);
  }

  static Future<RsaPssPublicKey> importJsonWebKey(
    Map<String, dynamic> jwk,
    Hash hash,
  ) {
    ArgumentError.checkNotNull(jwk, 'jwk');
    ArgumentError.checkNotNull(hash, 'hash');

    return impl.rsaPssPublicKey_importJsonWebKey(jwk, hash);
  }

  Future<bool> verifyBytes(
    List<int> signature,
    List<int> data,
    int saltLength,
  );

  Future<bool> verifyStream(
    List<int> signature,
    Stream<List<int>> data,
    int saltLength,
  );

  Future<Uint8List> exportSpkiKey();

  Future<Map<String, dynamic>> exportJsonWebKey();
}
