part of impl_js;

final _ecdsaAlgorithmName = 'ECDSA';

Future<EcdsaPrivateKey> ecdsaPrivateKey_importPkcs8Key(
  List<int> keyData,
  EllipticCurve curve,
) async {
  return _EcdsaPrivateKey(await _importKey(
    'pkcs8',
    keyData,
    subtle.Algorithm(
      name: _ecdsaAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesSign,
    'private',
  ));
}

Future<EcdsaPrivateKey> ecdsaPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async {
  return _EcdsaPrivateKey(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(
      name: _ecdsaAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesSign,
    'private',
  ));
}

Future<KeyPair<EcdsaPrivateKey, EcdsaPublicKey>> ecdsaPrivateKey_generateKey(
  EllipticCurve curve,
) async {
  final pair = await _generateKeyPair(
    subtle.Algorithm(
      name: _ecdsaAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesSignVerify,
  );
  return _KeyPair(
    privateKey: _EcdsaPrivateKey(pair.privateKey),
    publicKey: _EcdsaPublicKey(pair.publicKey),
  );
}

Future<EcdsaPublicKey> ecdsaPublicKey_importRawKey(
  List<int> keyData,
  EllipticCurve curve,
) async {
  return _EcdsaPublicKey(await _importKey(
    'raw',
    keyData,
    subtle.Algorithm(
      name: _ecdsaAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesVerify,
    'public',
  ));
}

Future<EcdsaPublicKey> ecdsaPublicKey_importSpkiKey(
  List<int> keyData,
  EllipticCurve curve,
) async {
  return _EcdsaPublicKey(await _importKey(
    'spki',
    keyData,
    subtle.Algorithm(
      name: _ecdsaAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesVerify,
    'public',
  ));
}

Future<EcdsaPublicKey> ecdsaPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  EllipticCurve curve,
) async {
  return _EcdsaPublicKey(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(
      name: _ecdsaAlgorithmName,
      namedCurve: _curveToName(curve),
    ),
    _usagesVerify,
    'public',
  ));
}

class _EcdsaPrivateKey implements EcdsaPrivateKey {
  final subtle.CryptoKey _key;
  _EcdsaPrivateKey(this._key);

  @override
  Future<Uint8List> signBytes(List<int> data, Hash hash) async {
    return await _sign(
      subtle.Algorithm(
        name: _ecdsaAlgorithmName,
        hash: _getHashAlgorithm(hash),
      ),
      _key,
      data,
    );
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data, Hash hash) async {
    return await signBytes(await _bufferStream(data), hash);
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return await _exportJsonWebKey(_key);
  }

  @override
  Future<Uint8List> exportPkcs8Key() async {
    return await _exportKey('pkcs8', _key);
  }
}

class _EcdsaPublicKey implements EcdsaPublicKey {
  final subtle.CryptoKey _key;
  _EcdsaPublicKey(this._key);

  @override
  Future<bool> verifyBytes(
      List<int> signature, List<int> data, Hash hash) async {
    return await _verify(
      subtle.Algorithm(
        name: _ecdsaAlgorithmName,
        hash: _getHashAlgorithm(hash),
      ),
      _key,
      signature,
      data,
    );
  }

  @override
  Future<bool> verifyStream(
    List<int> signature,
    Stream<List<int>> data,
    Hash hash,
  ) async {
    return await verifyBytes(signature, await _bufferStream(data), hash);
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return await _exportJsonWebKey(_key);
  }

  @override
  Future<Uint8List> exportRawKey() async {
    return await _exportKey('raw', _key);
  }

  @override
  Future<Uint8List> exportSpkiKey() async {
    return await _exportKey('spki', _key);
  }
}
