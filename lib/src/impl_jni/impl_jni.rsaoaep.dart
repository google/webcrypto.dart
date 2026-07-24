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

part of 'impl_jni.dart';

final class _StaticRsaOaepPrivateKeyImpl
    implements StaticRsaOaepPrivateKeyImpl {
  const _StaticRsaOaepPrivateKeyImpl();

  @override
  Future<RsaOaepPrivateKeyImpl> importPkcs8Key(
    List<int> keyData,
    HashImpl hash,
  ) async {
    final h = _rsaHashFromHash(hash);
    return _RsaOaepPrivateKeyImpl(
      _importPkcs8RsaPrivateKey(_asUint8List(keyData)),
      h,
    );
  }

  @override
  Future<RsaOaepPrivateKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    HashImpl hash,
  ) async {
    final h = _rsaHashFromHash(hash);
    return _RsaOaepPrivateKeyImpl(
      _importJwkRsaPrivateKey(
        jwk,
        expectedAlg: h._rsaOaepJwkAlg,
        expectedUse: 'enc',
      ),
      h,
    );
  }

  @override
  Future<(RsaOaepPrivateKeyImpl, RsaOaepPublicKeyImpl)> generateKey(
    int modulusLength,
    BigInt publicExponent,
    HashImpl hash,
  ) async {
    final h = _rsaHashFromHash(hash);
    final keyPair = await _generateRsaKeyPair(modulusLength, publicExponent);
    return (
      _RsaOaepPrivateKeyImpl(
        _importPkcs8RsaPrivateKey(keyPair.privateKeyData),
        h,
      ),
      _RsaOaepPublicKeyImpl(_importSpkiRsaPublicKey(keyPair.publicKeyData), h),
    );
  }
}

final class _RsaOaepPrivateKeyImpl implements RsaOaepPrivateKeyImpl {
  _RsaOaepPrivateKeyImpl(this._key, this._hash);

  final _JcaKeyOwner _key;
  final _HashImpl _hash;

  @override
  Future<Uint8List> decryptBytes(List<int> data, {List<int>? label}) {
    return _rsaOaepEncryptDecrypt(
      _key,
      _hash,
      _asUint8List(data),
      label == null ? null : _asUint8List(label),
      encrypt: false,
    );
  }

  @override
  Future<Uint8List> exportPkcs8Key() async =>
      _exportEncodedRsaKey(_key, 'private');

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkRsaPrivateKey(
        _key,
        jwkAlg: _hash._rsaOaepJwkAlg,
        jwkUse: 'enc',
      );
}

final class _StaticRsaOaepPublicKeyImpl implements StaticRsaOaepPublicKeyImpl {
  const _StaticRsaOaepPublicKeyImpl();

  @override
  Future<RsaOaepPublicKeyImpl> importSpkiKey(
    List<int> keyData,
    HashImpl hash,
  ) async {
    final h = _rsaHashFromHash(hash);
    return _RsaOaepPublicKeyImpl(
      _importSpkiRsaPublicKey(_asUint8List(keyData)),
      h,
    );
  }

  @override
  Future<RsaOaepPublicKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    HashImpl hash,
  ) async {
    final h = _rsaHashFromHash(hash);
    return _RsaOaepPublicKeyImpl(
      _importJwkRsaPublicKey(
        jwk,
        expectedAlg: h._rsaOaepJwkAlg,
        expectedUse: 'enc',
      ),
      h,
    );
  }
}

final class _RsaOaepPublicKeyImpl implements RsaOaepPublicKeyImpl {
  _RsaOaepPublicKeyImpl(this._key, this._hash);

  final _JcaKeyOwner _key;
  final _HashImpl _hash;

  @override
  Future<Uint8List> encryptBytes(List<int> data, {List<int>? label}) {
    return _rsaOaepEncryptDecrypt(
      _key,
      _hash,
      _asUint8List(data),
      label == null ? null : _asUint8List(label),
      encrypt: true,
    );
  }

  @override
  Future<Uint8List> exportSpkiKey() async =>
      _exportEncodedRsaKey(_key, 'public');

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _exportJwkRsaPublicKey(_key, jwkAlg: _hash._rsaOaepJwkAlg, jwkUse: 'enc');
}

Future<Uint8List> _rsaOaepEncryptDecrypt(
  _JcaKeyOwner key,
  _HashImpl hash,
  Uint8List data,
  Uint8List? label, {
  required bool encrypt,
}) async {
  try {
    return jni.using((arena) {
      final transformation = 'RSA/ECB/OAEPPadding'.toJString()
        ..releasedBy(arena);
      final cipher = Cipher.getInstance(transformation);
      if (cipher == null) {
        throw AssertionError('JCA Cipher(RSA/ECB/OAEPPadding) returned null');
      }
      cipher.releasedBy(arena);

      final hashName = hash._jcaName.toJString()..releasedBy(arena);
      final mgfName = 'MGF1'.toJString()..releasedBy(arena);
      final mgfParameters = MGF1ParameterSpec(hashName)..releasedBy(arena);
      final labelBytes = arena.copyToJByteArray(label ?? Uint8List(0));
      final pSource = PSource$PSpecified(labelBytes)..releasedBy(arena);
      final parameters = OAEPParameterSpec(
        hashName,
        mgfName,
        mgfParameters,
        pSource,
      )..releasedBy(arena);

      final jcaKey = key.key.as(Key.type)..releasedBy(arena);
      cipher.init$2(
        encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
        jcaKey,
        parameters,
      );

      final input = arena.copyToJByteArray(data);
      final output = cipher.doFinal$2(input);
      if (output == null) {
        throw AssertionError('JCA RSA-OAEP returned null');
      }
      output.releasedBy(arena);
      return output.copyToDartBytes();
    });
  } on jni.JThrowable catch (e) {
    throw _rsaOperationError(
      e,
      encrypt
          ? 'JCA RSA-OAEP encryption failed'
          : 'JCA RSA-OAEP decryption failed',
    );
  }
}

extension _RsaOaepHashMetadata on _HashImpl {
  String get _rsaOaepJwkAlg {
    return switch (_jcaName) {
      'SHA-1' => 'RSA-OAEP',
      'SHA-256' => 'RSA-OAEP-256',
      'SHA-384' => 'RSA-OAEP-384',
      'SHA-512' => 'RSA-OAEP-512',
      _ => throw AssertionError('Unknown hash algorithm: $_jcaName'),
    };
  }
}
