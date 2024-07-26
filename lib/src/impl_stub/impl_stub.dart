library webcrypto.impl_stub;

import 'package:webcrypto/src/impl_interface/impl_interface.dart';

part 'impl_stub.aescbc.dart';

const WebCryptoImpl webCryptImpl = _WebCryptoImpl();

final class _WebCryptoImpl implements WebCryptoImpl {
  const _WebCryptoImpl();

  @override
  final aesCbcSecretKey = const _StaticAesCbcSecretKeyImpl();
}
