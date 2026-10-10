// Copyright 2026 Google LLC
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

// ignore_for_file: avoid_print

// #region example
import 'dart:convert' show utf8, base64;

import 'package:webcrypto/webcrypto.dart';

Future<void> main() async {
  // Provide a password to be used for key derivation.
  final key = await Pbkdf2SecretKey.importRawKey(
    utf8.encode('my-password-in-plain-text'),
  );

  // Derive a key from the password.
  final derivedKey = await key.deriveBits(
    256, // number of bits to derive.
    Hash.sha256,
    utf8.encode('unique salt'),
    100000,
  );

  // Print the derived key. This could also be used as the basis for other
  // new symmetric cryptographic keys.
  print(base64.encode(derivedKey));
}

// #endregion
