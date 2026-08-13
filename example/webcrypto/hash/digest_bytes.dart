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
import 'dart:convert' show base64, utf8;

import 'package:webcrypto/webcrypto.dart';

Future<void> main() async {
  // Convert 'hello world' to a byte array
  final bytesToHash = utf8.encode('hello world');

  // Compute hash of bytesToHash with sha-256
  List<int> hash = await Hash.sha256.digestBytes(bytesToHash);

  // Print the base64 encoded hash
  print(base64.encode(hash));
}

// #endregion
