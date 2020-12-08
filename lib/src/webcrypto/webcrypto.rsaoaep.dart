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
abstract class RsaOaepPrivateKey {
  RsaOaepPrivateKey._(); // keep the constructor private.

  static Future<RsaOaepPrivateKey> importPkcs8Key(
    List<int> keyData,
    Hash hash,
  ) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(hash, 'hash');

    return impl.rsaOaepPrivateKey_importPkcs8Key(keyData, hash);
  }

  static Future<RsaOaepPrivateKey> importJsonWebKey(
    Map<String, dynamic> jwk,
    Hash hash,
  ) {
    ArgumentError.checkNotNull(jwk, 'jwk');
    ArgumentError.checkNotNull(hash, 'hash');

    return impl.rsaOaepPrivateKey_importJsonWebKey(jwk, hash);
  }

  static Future<KeyPair<RsaOaepPrivateKey, RsaOaepPublicKey>> generateKey(
    int modulusLength,
    BigInt publicExponent,
    Hash hash,
  ) {
    ArgumentError.checkNotNull(modulusLength, 'modulusLength');
    ArgumentError.checkNotNull(publicExponent, 'publicExponent');
    ArgumentError.checkNotNull(hash, 'hash');

    return impl.rsaOaepPrivateKey_generateKey(
      modulusLength,
      publicExponent,
      hash,
    );
  }

  /// Note, that this interface does not support streaming because RSA-OAEP
  /// is not a streaming cipher, instead it is often used to encrypt a symmetric
  /// cipher key used with an AES variant.
  Future<Uint8List> decryptBytes(List<int> data, {List<int>? label});

  Future<Uint8List> exportPkcs8Key();

  Future<Map<String, dynamic>> exportJsonWebKey();
}

@sealed
abstract class RsaOaepPublicKey {
  RsaOaepPublicKey._(); // keep the constructor private.

  static Future<RsaOaepPublicKey> importSpkiKey(
    List<int> keyData,
    Hash hash,
  ) {
    ArgumentError.checkNotNull(keyData, 'keyData');
    ArgumentError.checkNotNull(hash, 'hash');

    return impl.rsaOaepPublicKey_importSpkiKey(keyData, hash);
  }

  static Future<RsaOaepPublicKey> importJsonWebKey(
    Map<String, dynamic> jwk,
    Hash hash,
  ) {
    ArgumentError.checkNotNull(jwk, 'jwk');
    ArgumentError.checkNotNull(hash, 'hash');

    return impl.rsaOaepPublicKey_importJsonWebKey(jwk, hash);
  }

  /// Note, that this interface does not support streaming because RSA-OAEP
  /// is not a streaming cipher, instead it is often used to encrypt a symmetric
  /// cipher key used with an AES variant.
  Future<Uint8List> encryptBytes(List<int> data, {List<int>? label});

  Future<Uint8List> exportSpkiKey();

  Future<Map<String, dynamic>> exportJsonWebKey();
}
