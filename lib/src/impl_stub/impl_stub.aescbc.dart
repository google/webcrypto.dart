part of 'impl_stub.dart';

final class _StaticAesCbcSecretKeyImpl implements StaticAesCbcSecretKeyImpl {
  const _StaticAesCbcSecretKeyImpl();

  @override
  Future<AesCbcSecretKeyImpl> importRawKey(List<int> keyData) =>
    throw UnimplementedError('Not implemented');

  @override
  Future<AesCbcSecretKeyImpl> importJsonWebKey(Map<String, dynamic> jwk) =>
    throw UnimplementedError('Not implemented');

  @override
  Future<AesCbcSecretKeyImpl> generateKey(int length) =>
    throw UnimplementedError('Not implemented');
}
