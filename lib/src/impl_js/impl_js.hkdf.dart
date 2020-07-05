part of impl_js;

final _hkdfAlgorithmName = 'HKDF';

Future<HkdfSecretKey> hkdfSecretKey_importRawKey(List<int> keyData) async {
  return _HkdfSecretKey(await _importKey(
    'raw',
    keyData,
    subtle.Algorithm(name: _hkdfAlgorithmName),
    _usagesDeriveBits,
    'secret',
    // Unlike all other key types it makes no sense to HkdfSecretKey to be
    // exported, and indeed webcrypto requires `extractable: false`.
    extractable: false,
  ));
}

class _HkdfSecretKey implements HkdfSecretKey {
  final subtle.CryptoKey _key;
  _HkdfSecretKey(this._key);

  @override
  Future<Uint8List> deriveBits(
    int length,
    Hash hash,
    List<int> salt,
    List<int> info,
  ) async {
    ArgumentError.checkNotNull(length, 'length');
    ArgumentError.checkNotNull(salt, 'salt');
    ArgumentError.checkNotNull(info, 'info');
    return await _deriveBits(
      subtle.Algorithm(
        name: _hkdfAlgorithmName,
        hash: _getHashAlgorithm(hash),
        salt: Uint8List.fromList(salt),
        info: Uint8List.fromList(info),
      ),
      _key,
      length,
    );
  }
}
