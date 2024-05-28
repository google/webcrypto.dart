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

@sealed
abstract class EcdhPrivateKey {
  EcdhPrivateKey._(); // keep the constructor private.

  /// Import [EcdhPrivateKey] in the [PKCS #8][1] format.
  ///
  /// [keyData] is the DER encoding of the PrivateKeyInfo structure specified in [RFC 5208](https://datatracker.ietf.org/doc/html/rfc5208).
  /// The [curve] specified must match the curved used in [keyData].
  /// 
  /// **Example**
  /// ```dart
  /// import 'package:pem/pem.dart';
  /// import 'package:webcrypto/webcrypto.dart';
  /// 
  /// // Read key data from a PEM encoded block. This will remove the
  /// // the padding, decode base64 and return the encoded bytes.
  /// List<int> keyData = PemCodec(PemLabel.privateKey).decode('''
  ///   -----BEGIN PRIVATE KEY----- 
  ///   MIGHAgEAMBMGByqGSM4.....
  ///   -----END PRIVATE KEY-----
  ///   ''');
  /// 
  /// 
  /// Future<void> main() async {
  ///   // Import the Private Key from a Binary PEM decoded data.
  ///   final privateKey = await EcdhPrivateKey.importPkcs8Key(
  ///     keyData,
  ///     EllipticCurve.p256,
  ///   );
  /// 
  ///  // Export the private key (print it in same format as it was given).
  ///  final exportedPkcs8Key = await privateKey.exportPkcs8Key();
  ///  print(PemCodec(PemLabel.privateKey).encode(exportedPkcs8Key));
  /// }
  /// ```
  /// 
  /// [1]: https://datatracker.ietf.org/doc/html/rfc5208
  static Future<EcdhPrivateKey> importPkcs8Key(
    List<int> keyData,
    EllipticCurve curve,
  ) {
    return impl.ecdhPrivateKey_importPkcs8Key(keyData, curve);
  }

  static Future<EcdhPrivateKey> importJsonWebKey(
    Map<String, dynamic> jwk,
    EllipticCurve curve,
  ) {
    return impl.ecdhPrivateKey_importJsonWebKey(jwk, curve);
  }

  static Future<KeyPair<EcdhPrivateKey, EcdhPublicKey>> generateKey(
    EllipticCurve curve,
  ) {
    return impl.ecdhPrivateKey_generateKey(curve);
  }

  // Note some webcrypto implementations (chrome, not firefox) supports passing
  // null for length (in this primitive). However, you can always know the right
  // length from the curve. Note p512 can provide up to: 528 bits!!!
  //
  // See: https://tools.ietf.org/html/rfc6090#section-4
  // Notice that this is not uniformly distributed, see also:
  // https://tools.ietf.org/html/rfc6090#appendix-B
  Future<Uint8List> deriveBits(int length, EcdhPublicKey publicKey);

  Future<Uint8List> exportPkcs8Key();

  Future<Map<String, dynamic>> exportJsonWebKey();
}

@sealed
abstract class EcdhPublicKey {
  EcdhPublicKey._(); // keep the constructor private.

  /// TODO: find out of this works on Firefox
  static Future<EcdhPublicKey> importRawKey(
    List<int> keyData,
    EllipticCurve curve,
  ) {
    return impl.ecdhPublicKey_importRawKey(keyData, curve);
  }

  /// ## Compatibility
  /// TODO: explain that Chrome can't import SPKI keys from Firefox < 72.
  ///       This is a bug in Chrome / BoringSSL (and package:webcrypto)
  ///
  /// Chrome / BoringSSL doesn't recognize `id-ecDH`, but only `id-ecPublicKey`,
  /// See: https://crbug.com/389400
  ///
  /// Chrome / BoringSSL exports `id-ecDH`, but Firefox exports
  /// `id-ecPublicKey`. Note that Firefox < 72 can import both SPKI keys
  /// exported by both Chrome, BoringSSL and Firefox. While Chrome and BoringSSL
  /// cannot import SPKI keys from Firefox < 72.
  ///
  /// Firefox 72 and later exports SPKI keys with OID `id-ecPublicKey`, thus,
  /// this is not a problem.
  static Future<EcdhPublicKey> importSpkiKey(
    List<int> keyData,
    EllipticCurve curve,
  ) {
    return impl.ecdhPublicKey_importSpkiKey(keyData, curve);
  }

  static Future<EcdhPublicKey> importJsonWebKey(
    Map<String, dynamic> jwk,
    EllipticCurve curve,
  ) {
    return impl.ecdhPublicKey_importJsonWebKey(jwk, curve);
  }

  Future<Uint8List> exportRawKey();

  /// Note: Due to bug in Chrome/BoringSSL, SPKI keys exported from Firefox < 72
  /// cannot be imported in Chrome/BoringSSL.
  /// See compatibility section in [EcdhPublicKey.importSpkiKey].
  Future<Uint8List> exportSpkiKey();

  Future<Map<String, dynamic>> exportJsonWebKey();
}
