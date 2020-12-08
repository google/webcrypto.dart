// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

  _KeyPair({required this.privateKey, required this.publicKey});
}
