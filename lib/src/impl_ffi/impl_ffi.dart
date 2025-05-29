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

// ignore_for_file: non_constant_identifier_names

library impl_ffi;

import 'dart:async';
import 'dart:ffi' show Allocator;
import 'dart:typed_data';
import 'dart:convert' show utf8, base64Url;
import 'dart:isolate';
import 'dart:ffi' as ffi;
import 'dart:math' as math;
import 'package:meta/meta.dart';
import 'package:webcrypto/src/third_party/boringssl/generated_bindings.dart';

import '../jsonwebkey.dart' show JsonWebKey;
import '../webcrypto/webcrypto.dart';
import '../impl_interface/impl_interface.dart';
import '../boringssl/lookup/lookup.dart' show ssl, ERR_GET_LIB, ERR_GET_REASON;

part 'impl_ffi.aescbc.dart';
part 'impl_ffi.aesctr.dart';
part 'impl_ffi.aesgcm.dart';
part 'impl_ffi.digest.dart';
part 'impl_ffi.ecdh.dart';
part 'impl_ffi.ecdsa.dart';
part 'impl_ffi.hkdf.dart';
part 'impl_ffi.hmac.dart';
part 'impl_ffi.pbkdf2.dart';
part 'impl_ffi.random.dart';
part 'impl_ffi.rsaoaep.dart';
part 'impl_ffi.rsapss.dart';
part 'impl_ffi.rsassapkcs1v15.dart';
part 'impl_ffi.utils.dart';
part 'impl_ffi.rsa_common.dart';
part 'impl_ffi.ec_common.dart';
part 'impl_ffi.aes_common.dart';

const WebCryptoImpl webCryptImpl = _WebCryptoImpl();

final class _WebCryptoImpl implements WebCryptoImpl {
  const _WebCryptoImpl();

  @override
  final aesCbcSecretKey = const _StaticAesCbcSecretKeyImpl();

  @override
  final aesCtrSecretKey = const _StaticAesCtrSecretKeyImpl();

  @override
  final aesGcmSecretKey = const _StaticAesGcmSecretKeyImpl();

  @override
  final hmacSecretKey = const _StaticHmacSecretKeyImpl();

  @override
  final pbkdf2SecretKey = const _StaticPbkdf2SecretKeyImpl();

  @override
  final ecdhPrivateKey = const _StaticEcdhPrivateKeyImpl();

  @override
  final ecdhPublicKey = const _StaticEcdhPublicKeyImpl();

  @override
  final ecdsaPrivateKey = const _StaticEcdsaPrivateKeyImpl();

  @override
  final ecdsaPublicKey = const _StaticEcdsaPublicKeyImpl();

  @override
  final rsaOaepPrivateKey = const _StaticRsaOaepPrivateKeyImpl();

  @override
  final rsaOaepPublicKey = const _StaticRsaOaepPublicKeyImpl();

  @override
  final hkdfSecretKey = const _StaticHkdfSecretKeyImpl();

  @override
  final rsaPssPrivateKey = const _StaticRsaPssPrivateKeyImpl();

  @override
  final rsaPssPublicKey = const _StaticRsaPssPublicKeyImpl();

  @override
  final rsaSsaPkcs1v15PrivateKey = const _StaticRsaSsaPkcs1V15PrivateKeyImpl();

  @override
  final rsaSsaPkcs1v15PublicKey = const _StaticRsaSsaPkcs1V15PublicKeyImpl();

  @override
  final sha1 = const _Sha1();

  @override
  final sha256 = const _Sha256();

  @override
  final sha384 = const _Sha384();

  @override
  final sha512 = const _Sha512();

  @override
  final random = const _RandomImpl();
}
