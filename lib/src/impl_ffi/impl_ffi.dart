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
library impl_ffi;

import 'dart:async';
import 'dart:ffi' show Allocator;
import 'dart:typed_data';
import 'dart:convert' show utf8, base64Url;
import 'dart:ffi' as ffi;
import 'dart:math' as math;
import 'package:meta/meta.dart';
import 'package:webcrypto/src/third_party/boringssl/generated_bindings.dart';

import '../jsonwebkey.dart' show JsonWebKey;
import '../webcrypto/webcrypto.dart';
import '../boringssl/lookup/lookup.dart'
    show ssl, dl, ERR_GET_LIB, ERR_GET_REASON;

part 'impl_ffi.aescbc.dart';
part 'impl_ffi.aesctr.dart';
part 'impl_ffi.aesgcm.dart';
part 'impl_ffi.digest.dart';
part 'impl_ffi.ecdh.dart';
part 'impl_ffi.ecdsa.dart';
part 'impl_ffi.hkdf.dart';
part 'impl_ffi.hmac.dart';
part 'impl_ffi.pbkdf2.dart';
part 'impl_ffi.random.dart';
part 'impl_ffi.rsaoaep.dart';
part 'impl_ffi.rsapss.dart';
part 'impl_ffi.rsassapkcs1v15.dart';
part 'impl_ffi.utils.dart';
part 'impl_ffi.rsa_common.dart';
part 'impl_ffi.ec_common.dart';
part 'impl_ffi.aes_common.dart';

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
