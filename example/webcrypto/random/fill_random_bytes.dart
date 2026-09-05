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
import 'dart:convert' show base64;
import 'dart:typed_data' show Uint8List;

import 'package:webcrypto/webcrypto.dart';

void main() {
  // Allocate a byte array of 64 bytes.
  final bytes = Uint8List(64);

  // Fill with random bytes.
  fillRandomBytes(bytes);

  // Print base64 encoded random bytes.
  print(base64.encode(bytes));
}

// #endregion
