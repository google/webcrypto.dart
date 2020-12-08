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

//ignore_for_file: non_constant_identifier_names

import 'dart:async';
import 'dart:typed_data';

import 'webcrypto/webcrypto.dart';

final _notImplemented = throw UnimplementedError('Not implemented');

//---------------------- Random Bytes

void fillRandomBytes(TypedData destination) {
  throw _notImplemented;
}

//---------------------- Hash Algorithms

class _UnimplementedHash implements Hash {
  const _UnimplementedHash();

  @override
  Future<Uint8List> digestBytes(List<int> data) => throw _notImplemented;

  @override
  Future<Uint8List> digestStream(Stream<List<int>> data) =>
      throw _notImplemented;
}

const Hash sha1 = _UnimplementedHash();
const Hash sha256 = _UnimplementedHash();
const Hash sha384 = _UnimplementedHash();
const Hash sha512 = _UnimplementedHash();

//---------------------- HMAC
Future<HmacSecretKey> hmacSecretKey_importRawKey(
  List<int> keyData,
  Hash hash, {
  int? length,
}) =>
    throw _notImplemented;

Future<HmacSecretKey> hmacSecretKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash, {
  int? length,
}) =>
    throw _notImplemented;

Future<HmacSecretKey> hmacSecretKey_generateKey(Hash hash, {int? length}) =>
    throw _notImplemented;

//---------------------- RSASSA_PKCS1_v1_5

Future<RsassaPkcs1V15PrivateKey> rsassaPkcs1V15PrivateKey_importPkcs8Key(
  List<int> keyData,
  Hash hash,
) =>
    throw _notImplemented;

Future<RsassaPkcs1V15PrivateKey> rsassaPkcs1V15PrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) =>
    throw _notImplemented;

Future<KeyPair<RsassaPkcs1V15PrivateKey, RsassaPkcs1V15PublicKey>>
    rsassaPkcs1V15PrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  Hash hash,
) =>
        throw _notImplemented;

Future<RsassaPkcs1V15PublicKey> rsassaPkcs1V15PublicKey_importSpkiKey(
  List<int> keyData,
  Hash hash,
) =>
    throw _notImplemented;

Future<RsassaPkcs1V15PublicKey> rsassaPkcs1V15PublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) =>
    throw _notImplemented;

//---------------------- RSA-PSS

Future<RsaPssPrivateKey> rsaPssPrivateKey_importPkcs8Key(
  List<int> keyData,
  Hash hash,
) =>
    throw _notImplemented;

Future<RsaPssPrivateKey> rsaPssPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) =>
    throw _notImplemented;

Future<KeyPair<RsaPssPrivateKey, RsaPssPublicKey>> rsaPssPrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  Hash hash,
) =>
    throw _notImplemented;

Future<RsaPssPublicKey> rsaPssPublicKey_importSpkiKey(
  List<int> keyData,
  Hash hash,
) =>
    throw _notImplemented;

Future<RsaPssPublicKey> rsaPssPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) =>
    throw _notImplemented;

//---------------------- ECDSA

Future<EcdsaPrivateKey> ecdsaPrivateKey_importPkcs8Key(
  List<int> keyData,
  EllipticCurve curve,
) =>
    throw _notImplemented;

Future<EcdsaPrivateKey> ecdsaPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) =>
    throw _notImplemented;

Future<KeyPair<EcdsaPrivateKey, EcdsaPublicKey>> ecdsaPrivateKey_generateKey(
  EllipticCurve curve,
) =>
    throw _notImplemented;

Future<EcdsaPublicKey> ecdsaPublicKey_importRawKey(
  List<int> keyData,
  EllipticCurve curve,
) =>
    throw _notImplemented;

Future<EcdsaPublicKey> ecdsaPublicKey_importSpkiKey(
  List<int> keyData,
  EllipticCurve curve,
) =>
    throw _notImplemented;

Future<EcdsaPublicKey> ecdsaPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) =>
    throw _notImplemented;

//---------------------- RSA-OAEP

Future<RsaOaepPrivateKey> rsaOaepPrivateKey_importPkcs8Key(
  List<int> keyData,
  Hash hash,
) =>
    throw _notImplemented;

Future<RsaOaepPrivateKey> rsaOaepPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) =>
    throw _notImplemented;

Future<KeyPair<RsaOaepPrivateKey, RsaOaepPublicKey>>
    rsaOaepPrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  Hash hash,
) =>
        throw _notImplemented;

Future<RsaOaepPublicKey> rsaOaepPublicKey_importSpkiKey(
  List<int> keyData,
  Hash hash,
) =>
    throw _notImplemented;

Future<RsaOaepPublicKey> rsaOaepPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) =>
    throw _notImplemented;

//---------------------- AES-CTR

Future<AesCtrSecretKey> aesCtr_importRawKey(List<int> keyData) =>
    throw _notImplemented;

Future<AesCtrSecretKey> aesCtr_importJsonWebKey(Map<String, dynamic> jwk) =>
    throw _notImplemented;

Future<AesCtrSecretKey> aesCtr_generateKey(int length) => throw _notImplemented;

//---------------------- AES-CBC

Future<AesCbcSecretKey> aesCbc_importRawKey(List<int> keyData) =>
    throw _notImplemented;

Future<AesCbcSecretKey> aesCbc_importJsonWebKey(Map<String, dynamic> jwk) =>
    throw _notImplemented;

Future<AesCbcSecretKey> aesCbc_generateKey(int length) => throw _notImplemented;

//---------------------- AES-GCM

Future<AesGcmSecretKey> aesGcm_importRawKey(List<int> keyData) =>
    throw _notImplemented;

Future<AesGcmSecretKey> aesGcm_importJsonWebKey(Map<String, dynamic> jwk) =>
    throw _notImplemented;

Future<AesGcmSecretKey> aesGcm_generateKey(int length) => throw _notImplemented;

//---------------------- ECDH

Future<EcdhPrivateKey> ecdhPrivateKey_importPkcs8Key(
  List<int> keyData,
  EllipticCurve curve,
) =>
    throw _notImplemented;

Future<EcdhPrivateKey> ecdhPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) =>
    throw _notImplemented;

Future<KeyPair<EcdhPrivateKey, EcdhPublicKey>> ecdhPrivateKey_generateKey(
  EllipticCurve curve,
) =>
    throw _notImplemented;

Future<EcdhPublicKey> ecdhPublicKey_importRawKey(
  List<int> keyData,
  EllipticCurve curve,
) =>
    throw _notImplemented;

Future<EcdhPublicKey> ecdhPublicKey_importSpkiKey(
  List<int> keyData,
  EllipticCurve curve,
) =>
    throw _notImplemented;

Future<EcdhPublicKey> ecdhPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) =>
    throw _notImplemented;

//---------------------- HKDF

Future<HkdfSecretKey> hkdfSecretKey_importRawKey(List<int> keyData) =>
    throw _notImplemented;

//---------------------- PBKDF2

Future<Pbkdf2SecretKey> pbkdf2SecretKey_importRawKey(List<int> keyData) =>
    throw _notImplemented;
