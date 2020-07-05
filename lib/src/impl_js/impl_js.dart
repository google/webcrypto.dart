// ignore_for_file: non_constant_identifier_names

library impl_js;

import 'dart:async';
import 'dart:typed_data';

import '../webcrypto/webcrypto.dart';
import '../crypto_subtle.dart' as subtle;

part 'impl_js.aescbc.dart';
part 'impl_js.aesctr.dart';
part 'impl_js.aesgcm.dart';
part 'impl_js.digest.dart';
part 'impl_js.ecdh.dart';
part 'impl_js.ecdsa.dart';
part 'impl_js.hkdf.dart';
part 'impl_js.hmac.dart';
part 'impl_js.pbkdf2.dart';
part 'impl_js.random.dart';
part 'impl_js.rsaoaep.dart';
part 'impl_js.rsapss.dart';
part 'impl_js.rsassapkcs1v15.dart';
part 'impl_js.utils.dart';

/// Implementation of [OperationError].
class _OperationError extends Error implements OperationError {
  final String _message;
  _OperationError(this._message);
  @override
  String toString() => _message;
}

/// Implementation of [KeyPair].
class _KeyPair<S, T> implements KeyPair<S, T> {
  @override
  final S privateKey;

  @override
  final T publicKey;

  _KeyPair({this.privateKey, this.publicKey});
}
