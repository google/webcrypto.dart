// Copyright 2025 Google LLC
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

part of 'impl_js.dart';

const _ed25519Algorithm = subtle.Algorithm(name: 'Ed25519');

final class _StaticEd25519PrivateKeyImpl
    implements StaticEd25519PrivateKeyImpl {
  const _StaticEd25519PrivateKeyImpl();

  @override
  Future<(Ed25519PrivateKeyImpl, Ed25519PublicKeyImpl)> generateKey() async {
    final kp = await _generateKeyPair(
      _ed25519Algorithm,
      _usagesSignVerify,
    );
    return (
      _Ed25519PrivateKeyImpl(kp.privateKey),
      _Ed25519PublicKeyImpl(kp.publicKey),
    );
  }

  @override
  Future<Ed25519PrivateKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
  ) async {
    return _Ed25519PrivateKeyImpl(
      await _importJsonWebKey(jwk, _ed25519Algorithm, ['sign'], 'private'),
    );
  }

  @override
  Future<Ed25519PrivateKeyImpl> importPkcs8Key(List<int> keyData) async {
    return _Ed25519PrivateKeyImpl(
      await _importKey(
        'pkcs8',
        keyData,
        _ed25519Algorithm,
        _usagesSign,
        'private',
      ),
    );
  }
}

final class _Ed25519PrivateKeyImpl implements Ed25519PrivateKeyImpl {
  final subtle.JSCryptoKey _key;

  _Ed25519PrivateKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'Ed25519PrivateKeyImpl\'';
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() => _exportJsonWebKey(_key);

  @override
  Future<Uint8List> exportPkcs8Key() => _exportKey('pkcs8', _key);

  @override
  Future<Uint8List> signBytes(List<int> data) async {
    final sig = await subtle.sign(
      _ed25519Algorithm,
      _key,
      Uint8List.fromList(data),
    );
    return sig.asUint8List();
  }
}

final class _StaticEd25519PublicKeyImpl implements StaticEd25519PublicKeyImpl {
  const _StaticEd25519PublicKeyImpl();

  @override
  Future<Ed25519PublicKeyImpl> importJsonWebKey(
    Map<String, dynamic> jwk,
  ) async {
    return _Ed25519PublicKeyImpl(
      await _importJsonWebKey(
        jwk,
        _ed25519Algorithm,
        _usagesVerify,
        'public',
      ),
    );
  }

  @override
  Future<Ed25519PublicKeyImpl> importRawKey(List<int> keyData) async {
    return _Ed25519PublicKeyImpl(
      await _importKey(
        'raw',
        keyData,
        _ed25519Algorithm,
        _usagesVerify,
        'public',
      ),
    );
  }

  @override
  Future<Ed25519PublicKeyImpl> importSpkiKey(List<int> keyData) async {
    return _Ed25519PublicKeyImpl(
      await _importKey(
        'spki',
        keyData,
        _ed25519Algorithm,
        _usagesVerify,
        'public',
      ),
    );
  }
}

final class _Ed25519PublicKeyImpl implements Ed25519PublicKeyImpl {
  final subtle.JSCryptoKey _key;

  _Ed25519PublicKeyImpl(this._key);

  @override
  String toString() {
    return 'Instance of \'Ed25519PublicKeyImpl\'';
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() => _exportJsonWebKey(_key);

  @override
  Future<Uint8List> exportRawKey() => _exportKey('raw', _key);

  @override
  Future<Uint8List> exportSpkiKey() => _exportKey('spki', _key);

  @override
  Future<bool> verifyBytes(List<int> signature, List<int> data) async {
    return await subtle.verify(
      _ed25519Algorithm,
      _key,
      Uint8List.fromList(signature),
      Uint8List.fromList(data),
    );
  }
}
