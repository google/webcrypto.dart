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

//---------------------- RSA-OAEP

//---------------------- AES-CTR

//---------------------- AES-CBC

//---------------------- AES-GCM

//---------------------- ECDH

//---------------------- HKDF

Future<HkdfSecretKey> hkdfSecretKey_importRawKey(List<int> keyData) =>
    throw _notImplemented;

//---------------------- PBKDF2
