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
import 'package:webcrypto/webcrypto.dart';
import 'package:pem/pem.dart';

Future<void> main() async {
  // Read key data from PEM encoded block. This will remove the
  // '----BEGIN...' padding, decode base64 and return encoded bytes.
  List<int> keyData = PemCodec(PemLabel.privateKey).decode("""
    -----BEGIN PRIVATE KEY-----
    MIGEAgEAMBAGByqG...
    -----END PRIVATE KEY-----
  """);

  // Import private key from binary PEM decoded data.
  final privateKey = await RsaOaepPrivateKey.importPkcs8Key(
    keyData,
    Hash.sha256,
  );

  // Export the key again (print it in same format as it was given).
  List<int> rawKeyData = await privateKey.exportPkcs8Key();
  print(PemCodec(PemLabel.privateKey).encode(rawKeyData));
}

// #endregion
