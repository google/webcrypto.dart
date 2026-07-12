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

/// Experimental JNI/JCA backend for the Android JCA exploration branch.
///
/// During exploration the Android JCA branch may temporarily wire native builds
/// directly to this backend. The final FFI-vs-JNI selection mechanism can be
/// settled once enough primitives exist to compare behavior across backends.
library;

import 'dart:async';
import 'dart:convert' show base64Url;
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:jni/jni.dart' as jni;
import 'package:webcrypto/src/impl_interface/impl_interface.dart';

import '../jsonwebkey.dart' show JsonWebKey;
import '../third_party/jca/generated_bindings.dart';

part 'impl_jni.aes_common.dart';
part 'impl_jni.aescbc.dart';
part 'impl_jni.aesctr.dart';
part 'impl_jni.aesgcm.dart';
part 'impl_jni.hmac.dart';
part 'impl_jni.pbkdf2.dart';
part 'impl_jni.ecdh.dart';
part 'impl_jni.ecdsa.dart';
part 'impl_jni.rsaoaep.dart';
part 'impl_jni.hkdf.dart';
part 'impl_jni.rsapss.dart';
part 'impl_jni.rsassapkcs1v15.dart';
part 'impl_jni.digest.dart';
part 'impl_jni.random.dart';
part 'impl_jni.utils.dart';

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
  final sha1 = const _HashImpl('SHA-1');

  @override
  final sha256 = const _HashImpl('SHA-256');

  @override
  final sha384 = const _HashImpl('SHA-384');

  @override
  final sha512 = const _HashImpl('SHA-512');

  @override
  final random = const _RandomImpl();
}
