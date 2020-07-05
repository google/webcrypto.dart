part of impl_js;

final _aesCtrAlgorithm = subtle.Algorithm(name: 'AES-CTR');

Future<AesCtrSecretKey> aesCtr_importRawKey(List<int> keyData) async {
  return _AesCtrSecretKey(await _importKey(
    'raw',
    keyData,
    _aesCtrAlgorithm,
    _usagesEncryptDecrypt,
    'secret',
  ));
}

Future<AesCtrSecretKey> aesCtr_importJsonWebKey(
  Map<String, dynamic> jwk,
) async {
  return _AesCtrSecretKey(await _importJsonWebKey(
    jwk,
    _aesCtrAlgorithm,
    _usagesEncryptDecrypt,
    'secret',
  ));
}

Future<AesCtrSecretKey> aesCtr_generateKey(int length) async {
  return _AesCtrSecretKey(await _generateKey(
    subtle.Algorithm(
      name: _aesCtrAlgorithm.name,
      length: length,
    ),
    _usagesEncryptDecrypt,
    'secret',
  ));
}

class _AesCtrSecretKey implements AesCtrSecretKey {
  final subtle.CryptoKey _key;
  _AesCtrSecretKey(this._key);

  @override
  Future<Uint8List> decryptBytes(
    List<int> data,
    List<int> counter,
    int length,
  ) async {
    ArgumentError.checkNotNull(counter, 'counter');
    ArgumentError.checkNotNull(length, 'length');
    return await _decrypt(
      subtle.Algorithm(
        name: _aesCtrAlgorithm.name,
        counter: Uint8List.fromList(counter),
        length: length,
      ),
      _key,
      data,
    );
  }

  @override
  Stream<Uint8List> decryptStream(
    Stream<List<int>> data,
    List<int> counter,
    int length,
  ) async* {
    yield await decryptBytes(await _bufferStream(data), counter, length);
  }

  @override
  Future<Uint8List> encryptBytes(
    List<int> data,
    List<int> counter,
    int length,
  ) async {
    ArgumentError.checkNotNull(counter, 'counter');
    ArgumentError.checkNotNull(length, 'length');
    return await _encrypt(
      subtle.Algorithm(
        name: _aesCtrAlgorithm.name,
        counter: Uint8List.fromList(counter),
        length: length,
      ),
      _key,
      data,
    );
  }

  @override
  Stream<Uint8List> encryptStream(
    Stream<List<int>> data,
    List<int> counter,
    int length,
  ) async* {
    yield await encryptBytes(await _bufferStream(data), counter, length);
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async {
    return await _exportJsonWebKey(_key);
  }

  @override
  Future<Uint8List> exportRawKey() async {
    return await _exportKey('raw', _key);
  }
}
