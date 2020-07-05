part of impl_js;

final _rsaPssAlgorithmName = 'RSA-PSS';

Future<RsaPssPrivateKey> rsaPssPrivateKey_importPkcs8Key(
  List<int> keyData,
  Hash hash,
) async {
  return _RsaPssPrivateKey(await _importKey(
    'pkcs8',
    keyData,
    subtle.Algorithm(name: _rsaPssAlgorithmName, hash: _getHashAlgorithm(hash)),
    _usagesSign,
    'private',
  ));
}

Future<RsaPssPrivateKey> rsaPssPrivateKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) async {
  return _RsaPssPrivateKey(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(name: _rsaPssAlgorithmName, hash: _getHashAlgorithm(hash)),
    _usagesSign,
    'private',
  ));
}

Future<KeyPair<RsaPssPrivateKey, RsaPssPublicKey>> rsaPssPrivateKey_generateKey(
  int modulusLength,
  BigInt publicExponent,
  Hash hash,
) async {
  final pair = await _generateKeyPair(
    subtle.Algorithm(
      name: _rsaPssAlgorithmName,
      hash: _getHashAlgorithm(hash),
      publicExponent: _publicExponentAsBuffer(publicExponent),
      modulusLength: modulusLength,
    ),
    _usagesSignVerify,
  );
  return _KeyPair(
    privateKey: _RsaPssPrivateKey(pair.privateKey),
    publicKey: _RsaPssPublicKey(pair.publicKey),
  );
}

Future<RsaPssPublicKey> rsaPssPublicKey_importSpkiKey(
  List<int> keyData,
  Hash hash,
) async {
  return _RsaPssPublicKey(await _importKey(
    'spki',
    keyData,
    subtle.Algorithm(name: _rsaPssAlgorithmName, hash: _getHashAlgorithm(hash)),
    _usagesVerify,
    'public',
  ));
}

Future<RsaPssPublicKey> rsaPssPublicKey_importJsonWebKey(
  Map<String, dynamic> jwk,
  Hash hash,
) async {
  return _RsaPssPublicKey(await _importJsonWebKey(
    jwk,
    subtle.Algorithm(name: _rsaPssAlgorithmName, hash: _getHashAlgorithm(hash)),
    _usagesVerify,
    'public',
  ));
}

class _RsaPssPrivateKey implements RsaPssPrivateKey {
  final subtle.CryptoKey _key;
  _RsaPssPrivateKey(this._key);

  @override
  Future<Uint8List> signBytes(List<int> data, int saltLength) async {
    return await _sign(
      subtle.Algorithm(name: _rsaPssAlgorithmName, saltLength: saltLength),
      _key,
      data,
    );
  }

  @override
  Future<Uint8List> signStream(Stream<List<int>> data, int saltLength) async {
    return await signBytes(await _bufferStream(data), saltLength);
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

class _RsaPssPublicKey implements RsaPssPublicKey {
  final subtle.CryptoKey _key;
  _RsaPssPublicKey(this._key);

  @override
  Future<bool> verifyBytes(
    List<int> signature,
    List<int> data,
    int saltLength,
  ) async {
    return await _verify(
      subtle.Algorithm(name: _rsaPssAlgorithmName, saltLength: saltLength),
      _key,
      signature,
      data,
    );
  }

  @override
  Future<bool> verifyStream(
    List<int> signature,
    Stream<List<int>> data,
    int saltLength,
  ) async {
    return await verifyBytes(signature, await _bufferStream(data), saltLength);
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return await _exportJsonWebKey(_key);
  }

  @override
  Future<Uint8List> exportSpkiKey() async {
    return await _exportKey('spki', _key);
  }
}
