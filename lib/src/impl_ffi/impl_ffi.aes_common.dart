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

part of impl_ffi;

Uint8List _aesImportRawKey(List<int> keyData) {
  ArgumentError.checkNotNull(keyData, 'keyData');
  if (keyData.length == 24) {
    // 192-bit AES is intentionally unsupported, see https://crbug.com/533699
    // If not supported in Chrome, there is not reason to support it in Dart.
    throw UnsupportedError('192-bit AES keys are not supported');
  }
  if (keyData.length != 16 && keyData.length != 32) {
    throw FormatException('keyData for AES must be 128 or 256 bits');
  }
  return Uint8List.fromList(keyData);
}

Uint8List _aesImportJwkKey(
  Map<String, dynamic> jwk, {
  required String expectedJwkAlgSuffix,
}) {
  ArgumentError.checkNotNull(jwk, 'jwk');

  final k = JsonWebKey.fromJson(jwk);

  void checkJwk(bool condition, String prop, String message) =>
      _checkData(condition, message: 'JWK property "$prop" $message');

  checkJwk(k.kty == 'oct', 'kty', 'must be "oct"');
  checkJwk(k.k != null, 'k', 'must be present');
  checkJwk(k.use == null || k.use == 'enc', 'use', 'must be "enc", if present');

  final keyData = _jwkDecodeBase64UrlNoPadding(k.k!, 'k');
  if (keyData.length == 24) {
    // 192-bit AES is intentionally unsupported, see https://crbug.com/533699
    // If not supported in Chrome, there is not reason to support it in Dart.
    throw UnsupportedError('192-bit AES keys are not supported');
  }
  checkJwk(keyData.length == 16 || keyData.length == 32, 'k',
      'must be a 128 or 256 bit key');

  final expectedAlgPrefix = keyData.length == 16 ? 'A128' : 'A256';
  final expectedAlg = expectedAlgPrefix + expectedJwkAlgSuffix;

  checkJwk(
    k.alg == null || k.alg == expectedAlg,
    'alg',
    'must be "$expectedAlg", if present',
  );

  return keyData;
}

Map<String, dynamic> _aesExportJwkKey(
  List<int> keyData, {
  required String jwkAlgSuffix,
}) {
  assert(keyData.length == 16 || keyData.length == 32);
  final algPrefix = keyData.length == 16 ? 'A128' : 'A256';

  return JsonWebKey(
    kty: 'oct',
    use: 'enc',
    alg: algPrefix + jwkAlgSuffix,
    k: _jwkEncodeBase64UrlNoPadding(keyData),
  ).toJson();
}

Uint8List _aesGenerateKey(int length) {
  ArgumentError.checkNotNull(length, 'length');
  if (length == 192) {
    // 192-bit AES is intentionally unsupported, see https://crbug.com/533699
    // If not supported in Chrome, there is not reason to support it in Dart.
    throw UnsupportedError('192-bit AES keys are not supported');
  }
  if (length != 128 && length != 256) {
    throw FormatException('keyData for AES must be 128 or 256 bits');
  }
  final keyData = Uint8List(length ~/ 8);
  fillRandomBytes(keyData);
  return keyData;
}
