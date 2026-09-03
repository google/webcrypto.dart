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

part of 'webcrypto.dart';

/// Fill [destination] with cryptographically random values.
///
/// Does not accept a [destination] larger than `65536` bytes, use multiple
/// calls to obtain more random bytes.
///
/// **Example**
/// {@example /example/webcrypto/random/fill_random_bytes.dart#example}
void fillRandomBytes(
  TypedData destination,
  // Note: Uint8List and friends all implement TypedData, but dartdoc has a bug
  //       where it's not reporting this.
) {
  if (destination is! Uint8List &&
      destination is! Uint16List &&
      destination is! Uint32List &&
      destination is! Int8List &&
      destination is! Int16List &&
      destination is! Int32List) {
    throw ArgumentError.value(
      destination,
      'destination',
      'unsupported TypedData type',
    );
  }

  // This limitation is given in the Web Cryptography Specification, see:
  // https://www.w3.org/TR/WebCryptoAPI/#Crypto-method-getRandomValues
  if (destination.lengthInBytes > 65536) {
    throw ArgumentError.value(
      destination,
      'destination',
      'array of more than 65536 bytes is not allowed',
    );
  }

  webCryptImpl.random.fillRandomBytes(destination);
}
