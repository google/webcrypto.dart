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

library webcrypto.impl_stub;

import 'package:webcrypto/src/impl_interface/impl_interface.dart';
import 'package:webcrypto/webcrypto.dart';

part 'impl_stub.aescbc.dart';
part 'impl_stub.aesctr.dart';
part 'impl_stub.hmac.dart';
part 'impl_stub.pbkdf2.dart';

const WebCryptoImpl webCryptImpl = _WebCryptoImpl();

final class _WebCryptoImpl implements WebCryptoImpl {
  const _WebCryptoImpl();

  @override
  final aesCbcSecretKey = const _StaticAesCbcSecretKeyImpl();

  @override
  final aesCtrSecretKey = const _StaticAesCtrSecretKeyImpl();

  @override
  final hmacSecretKey = const _StaticHmacSecretKeyImpl();

  @override
  final pbkdf2SecretKey = const _StaticPbkdf2SecretKeyImpl();
}
