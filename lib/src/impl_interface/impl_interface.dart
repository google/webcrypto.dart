library impl_stub;

import 'dart:typed_data';
import 'dart:async';


part 'impl_interface.aescbc.dart';

/// Interface to be provided by platform implementations.
///
/// A platform implementation of `package:webcrypto` must define a
/// constant `webCryptImpl` as follows:
/// ```dart
/// const WebCryptoImpl webCryptImpl = const _MyPlatformImplemetation();
/// ```
///
/// The only platform implementations are:
///  * `lib/src/impl_ffi/impl_ffi.dart`,
///  * `lib/src/impl_js/impl_js.dart`, and,
///  * `lib/src/impl_stub/impl_stub.dart`.
///
/// These interfaces are not public and should not be implemented
/// outside this package. Should platform implementations ever become
/// plugable these interfaces will be renamed.
abstract interface class WebCryptoImpl {
  StaticAesCbcSecretKeyImpl get aesCbcSecretKey;
}
