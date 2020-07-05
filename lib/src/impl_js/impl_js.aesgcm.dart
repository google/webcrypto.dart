part of impl_js;

final _aesGcmAlgorithm = subtle.Algorithm(name: 'AES-GCM');

Future<AesGcmSecretKey> aesGcm_importRawKey(List<int> keyData) async {
  return _AesGcmSecretKey(await _importKey(
    'raw',
    keyData,
    _aesGcmAlgorithm,
    _usagesEncryptDecrypt,
    'secret',
  ));
}

Future<AesGcmSecretKey> aesGcm_importJsonWebKey(
  Map<String, dynamic> jwk,
) async {
  return _AesGcmSecretKey(await _importJsonWebKey(
    jwk,
    _aesGcmAlgorithm,
    _usagesEncryptDecrypt,
    'secret',
  ));
}

Future<AesGcmSecretKey> aesGcm_generateKey(int length) async {
  return _AesGcmSecretKey(await _generateKey(
    subtle.Algorithm(
      name: _aesGcmAlgorithm.name,
      length: length,
    ),
    _usagesEncryptDecrypt,
    'secret',
  ));
}

class _AesGcmSecretKey implements AesGcmSecretKey {
  final subtle.CryptoKey _key;
  _AesGcmSecretKey(this._key);

  @override
  Future<Uint8List> decryptBytes(
    List<int> data,
    List<int> iv, {
    List<int> additionalData,
    int tagLength = 128,
  }) async {
    ArgumentError.checkNotNull(iv, 'iv');
    // TODO: Ask lrn@ how to implement default parameters -- should null be special
    tagLength ??= 128;
    ArgumentError.checkNotNull(tagLength, 'tagLength');
    return await _decrypt(
      additionalData == null
          ? subtle.Algorithm(
              name: _aesGcmAlgorithm.name,
              iv: Uint8List.fromList(iv),
              tagLength: tagLength,
            )
          : subtle.Algorithm(
              name: _aesGcmAlgorithm.name,
              iv: Uint8List.fromList(iv),
              additionalData: Uint8List.fromList(additionalData),
              tagLength: tagLength,
            ),
      _key,
      data,
    );
  }

  @override
  Future<Uint8List> encryptBytes(
    List<int> data,
    List<int> iv, {
    List<int> additionalData,
    int tagLength = 128,
  }) async {
    ArgumentError.checkNotNull(iv, 'iv');
    tagLength ??= 128;
    ArgumentError.checkNotNull(tagLength, 'tagLength');
    return await _encrypt(
      additionalData == null
          ? subtle.Algorithm(
              name: _aesGcmAlgorithm.name,
              iv: Uint8List.fromList(iv),
              tagLength: tagLength,
            )
          : subtle.Algorithm(
              name: _aesGcmAlgorithm.name,
              iv: Uint8List.fromList(iv),
              additionalData: Uint8List.fromList(additionalData),
              tagLength: tagLength,
            ),
      _key,
      data,
    );
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
