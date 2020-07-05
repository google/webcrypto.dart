part of impl_js;

class _Hash implements Hash {
  final String _algorithm;
  const _Hash(this._algorithm);

  @override
  Future<Uint8List> digestBytes(List<int> data) async {
    return await _handleDomException(() async {
      final result = await subtle.promiseAsFuture(subtle.digest(
        _algorithm,
        Uint8List.fromList(data),
      ));
      return result.asUint8List();
    });
  }

  @override
  Future<Uint8List> digestStream(Stream<List<int>> data) async {
    return await digestBytes(await _bufferStream(data));
  }
}

const Hash sha1 = _Hash('SHA-1');
const Hash sha256 = _Hash('SHA-256');
const Hash sha384 = _Hash('SHA-384');
const Hash sha512 = _Hash('SHA-512');

/// Get the algorithm from [hash] or throw an [ArgumentError].
String _getHashAlgorithm(Hash hash) {
  if (hash is _Hash) {
    return hash._algorithm;
  }
  throw ArgumentError.value(
    hash,
    'hash',
    'Only built-in hash functions is allowed',
  );
}
