// Copyright 2026 Google LLC
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

_HashImpl _hmacHashFromHash(HashImpl hash) {
  if (hash is _HashImpl) {
    return hash;
  }
  throw AssertionError('Custom implementations of HashImpl are not supported.');
}

extension _HmacHashMetadata on _HashImpl {
  String get _hmacJcaName {
    return switch (_jcaName) {
      'SHA-1' => 'HmacSHA1',
      'SHA-256' => 'HmacSHA256',
      'SHA-384' => 'HmacSHA384',
      'SHA-512' => 'HmacSHA512',
      _ => throw AssertionError('Unknown hash algorithm: $_jcaName'),
    };
  }

  String get _hmacJwkAlg {
    return switch (_jcaName) {
      'SHA-1' => 'HS1',
      'SHA-256' => 'HS256',
      'SHA-384' => 'HS384',
      'SHA-512' => 'HS512',
      _ => throw AssertionError('Unknown hash algorithm: $_jcaName'),
    };
  }

  int get _hmacDefaultLengthBits {
    return switch (_jcaName) {
      'SHA-1' => 160,
      'SHA-256' => 256,
      'SHA-384' => 384,
      'SHA-512' => 512,
      _ => throw AssertionError('Unknown hash algorithm: $_jcaName'),
    };
  }
}

final class _StaticHmacSecretKeyImpl implements StaticHmacSecretKeyImpl {
  const _StaticHmacSecretKeyImpl();

  @override
  Future<HmacSecretKeyImpl> importRawKey(
    List<int> keyData,
    HashImpl hash, {
    int? length,
  }) async => _HmacSecretKeyImpl(
    _asUint8ListZeroedToBitLength(keyData, length),
    _hmacHashFromHash(hash),
  );

  @override
  Future<HmacSecretKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
    HashImpl hash, {
    int? length,
  }) {
    final h = _hmacHashFromHash(hash);
    final key = JsonWebKey.fromJson(jwk);

    void checkJwk(bool condition, String prop, String message) =>
        _checkData(condition, 'JWK property "$prop" $message');

    checkJwk(key.kty == 'oct', 'kty', 'must be "oct"');
    checkJwk(key.k != null, 'k', 'must be present');
    checkJwk(
      key.use == null || key.use == 'sig',
      'use',
      'must be "sig", if present',
    );
    checkJwk(
      key.alg == null || key.alg == h._hmacJwkAlg,
      'alg',
      'must be "${h._hmacJwkAlg}"',
    );

    final keyData = _jwkDecodeBase64UrlNoPadding(key.k!, 'k');
    return importRawKey(keyData, hash, length: length);
  }

  @override
  Future<HmacSecretKeyImpl> generateKey(HashImpl hash, {int? length = 32}) {
    final h = _hmacHashFromHash(hash);
    length ??= h._hmacDefaultLengthBits;
    final keyData = _randomBytes((length + 7) ~/ 8);
    return importRawKey(keyData, hash, length: length);
  }
}

final class _HmacSecretKeyImpl implements HmacSecretKeyImpl {
  _HmacSecretKeyImpl(this._keyData, this._hash);

  final Uint8List _keyData;
  final _HashImpl _hash;

  @override
  Future<Uint8List> signBytes(List<int> data) async {
    return jni.using((arena) {
      final mac = _createMac(arena);
      final input = arena.copyToJByteArray(_asUint8List(data));
      return _copyMacResult(arena, mac.doFinal$2(input));
    });
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data) async {
    final arena = jni.Arena();
    try {
      final mac = _createMac(arena);
      final buffer = jni.JByteArray(_defaultChunkSize)..releasedBy(arena);
      await for (final chunk in data) {
        _updateMacWithChunk(mac, buffer, chunk);
      }

      return _copyMacResult(arena, mac.doFinal());
    } finally {
      arena.releaseAll();
    }
  }

  @override
  Future<bool> verifyBytes(List<int> signature, List<int> data) async {
    return _verifySignature(await signBytes(data), signature);
  }

  @override
  Future<bool> verifyStream(List<int> signature, Stream<List<int>> data) async {
    return _verifySignature(await signStream(data), signature);
  }

  @override
  Future<Uint8List> exportRawKey() async => Uint8List.fromList(_keyData);

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return JsonWebKey(
      kty: 'oct',
      use: 'sig',
      alg: _hash._hmacJwkAlg,
      k: _jwkEncodeBase64UrlNoPadding(_keyData),
    ).toJson();
  }

  Mac _createMac(jni.Arena arena) {
    final algorithm = _hash._hmacJcaName.toJString()..releasedBy(arena);
    final keyData = arena.copyToJByteArray(_keyData);
    final key = SecretKeySpec(keyData, algorithm)..releasedBy(arena);

    final mac = Mac.getInstance(algorithm);
    if (mac == null) {
      throw AssertionError('JCA Mac(${_hash._hmacJcaName}) returned null');
    }
    mac.releasedBy(arena);
    mac.init(key);
    return mac;
  }

  void _updateMacWithChunk(Mac mac, jni.JByteArray buffer, List<int> chunk) {
    final bytes = _asUint8List(chunk);
    var offset = 0;
    while (offset < bytes.length) {
      final remaining = bytes.length - offset;
      final length = remaining < _defaultChunkSize
          ? remaining
          : _defaultChunkSize;
      buffer.setRange(0, length, bytes, offset);
      mac.update$2(buffer, 0, length);
      offset += length;
    }
  }

  Uint8List _copyMacResult(jni.Arena arena, jni.JByteArray? result) {
    if (result == null) {
      throw AssertionError('JCA Mac(${_hash._hmacJcaName}) returned null');
    }
    result.releasedBy(arena);
    return result.copyToDartBytes();
  }

  bool _verifySignature(Uint8List computedMac, List<int> suppliedSignature) {
    return jni.using((arena) {
      final computed = arena.copyToJByteArray(computedMac);
      final supplied = arena.copyToJByteArray(_asUint8List(suppliedSignature));
      return MessageDigest.isEqual(computed, supplied);
    });
  }
}
