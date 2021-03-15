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

Future<AesCtrSecretKey> aesCtr_importRawKey(List<int> keyData) async =>
    _AesCtrSecretKey(_aesImportRawKey(keyData));

Future<AesCtrSecretKey> aesCtr_importJsonWebKey(
  Map<String, dynamic> jwk,
) async =>
    _AesCtrSecretKey(_aesImportJwkKey(
      jwk,
      expectedJwkAlgSuffix: 'CTR',
    ));

Future<AesCtrSecretKey> aesCtr_generateKey(int length) async =>
    _AesCtrSecretKey(_aesGenerateKey(length));

BigInt _parseBigEndian(List<int> data, [int? bitLength]) {
  bitLength ??= data.length * 8;
  assert(bitLength <= data.length * 8);

  // Find the index of the first byte we have to read
  final init = data.length - (bitLength / 8).ceil();
  // Find the remainder bits when reading the first byte
  final remainder_bits = bitLength % 8;
  // If there is any remainder bits, we make a copy and zero-out the rest of the
  // initial byte
  if (remainder_bits != 0) {
    data = Uint8List.fromList(data);
    data[init] &= ~(0xff << remainder_bits);
  }
  // Parse BigInt as big-endian integer.
  var value = BigInt.from(0);
  for (var i = init; i < data.length; i++) {
    value = (value << 8) | BigInt.from(data[i] & 0xf);
  }
  return value;
}

Stream<Uint8List> _aesCtrEncryptOrDecrypt(
  Uint8List key,
  bool encrypt,
  Stream<List<int>> source,
  List<int> counter,
  int length,
) async* {
  // Heavily inspired by Chromium Web Crypto implementation, see:
  // https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/aes_ctr.cc#144

  final scope = _Scope();
  try {
    assert(counter.length == 16);
    assert(key.length == 16 || key.length == 32);
    final cipher =
        key.length == 16 ? ssl.EVP_aes_128_ctr() : ssl.EVP_aes_256_ctr();
    final blockSize = AES_BLOCK_SIZE;

    // Find the number of possible counter values, as the counter may not be
    // reused this will limit how much data we can process. If we get more data
    // than `blockSize * ctr_values`, Web Crypto will throw a `DataError`,
    // which we shall mirror by throwing a [FormatException].
    final ctr_values = BigInt.one << length;

    // Read the counter
    final ctr = _parseBigEndian(counter, length);

    // Number of bytes until wrap around. BoringSSL treats the counter as 128
    // bit counter that can be incremented. While web crypto specifies the
    // counter to be the first [length] bits of the `counter` parameter, and
    // the rest of the `counter` parameter is a nonce. Hence, when the counter
    // wraps around to zero, the left most `128 - length` bits should remain
    // static. Which is not the behavior BoringSSL implements. We can do this
    // with BoringSSL by managing the counter wrap-around manually. But to do
    // this we must track the number of blocks until wrap-around.
    var bytes_until_wraparound = (ctr_values - ctr) * BigInt.from(blockSize);

    // After wrap-around we cannot consume more than `ctr` blocks, or we'll
    // reuse the same counter value which is not allowed.
    var bytes_after_wraparound = ctr * BigInt.from(blockSize);

    final ctx = scope.create(ssl.EVP_CIPHER_CTX_new, ssl.EVP_CIPHER_CTX_free);
    _checkOpIsOne(ssl.EVP_CipherInit_ex(
      ctx,
      cipher,
      ffi.nullptr,
      scope.dataAsPointer(key),
      scope.dataAsPointer(counter),
      encrypt ? 1 : 0,
    ));

    const bufSize = 4096;

    // Allocate an input buffer
    final inBuf = scope<ffi.Uint8>(bufSize);
    final inData = inBuf.asTypedList(bufSize);

    // Allocate an output buffer, notice that BoringSSL says output cannot be
    // more than input size + blockSize - 1
    final outBuf = scope<ffi.Uint8>(bufSize + blockSize);
    final outData = outBuf.asTypedList(bufSize + blockSize);

    // Allocate and output length integer
    final outLen = scope<ffi.Int32>();

    // Process data from source
    var isBeforeWrapAround = true;
    await for (final data in source) {
      var offset = 0; // offset in data that we have consumed up-to.
      while (offset < data.length) {
        int M; // Number of bytes consumed in this iteration
        if (isBeforeWrapAround) {
          // Do not consume more bytes than allowed before wrap-around.
          M = math.min(bytes_until_wraparound.toInt(), data.length - offset);
          bytes_until_wraparound -= BigInt.from(M);
        } else {
          M = data.length - offset;
          // Do not consume more bytes than allowed after wrap-around
          if (bytes_after_wraparound.toInt() < M) {
            throw FormatException('input is too large for the counter length');
          }
          bytes_after_wraparound -= BigInt.from(M);
        }

        // Consume the first M bytes from data.
        var i = 0; // Number of bytes consumed, after offset
        while (i < M) {
          final N = math.min(M, bufSize);
          inData.setAll(0, data.skip(offset + i).take(N));

          _checkOpIsOne(ssl.EVP_CipherUpdate(
            ctx,
            outBuf,
            outLen,
            inBuf,
            N,
          ));
          if (outLen.value > 0) {
            yield outData.sublist(0, outLen.value);
          }
          i += N;
        }
        assert(i == M);
        offset += M;

        // Check if it's time to wrap-around
        if (isBeforeWrapAround && bytes_until_wraparound == BigInt.zero) {
          // Output final block of data before wrap-around
          _checkOpIsOne(ssl.EVP_CipherFinal_ex(ctx, outBuf, outLen));
          if (outLen.value > 0) {
            yield outData.sublist(0, outLen.value);
          }

          final counterWrappedAround = scope.dataAsPointer<ffi.Uint8>(counter);
          // Zero out the [length] right-most bits of [counterWrappedAround].
          final c = counterWrappedAround.asTypedList(16);
          final remainder_bits = length % 8;
          final counter_bytes = length ~/ 8;
          c.fillRange(c.length - counter_bytes, c.length, 0);
          if (remainder_bits != 0) {
            c[c.length - counter_bytes - 1] &= 0xff & (0xff << remainder_bits);
          }

          // Re-initialize the cipher context with counter wrapped around.
          _checkOpIsOne(ssl.EVP_CipherInit_ex(
            ctx,
            cipher,
            ffi.nullptr,
            scope.dataAsPointer(key),
            counterWrappedAround,
            encrypt ? 1 : 0,
          ));

          // Update state
          isBeforeWrapAround = false;
        }
      }
    }

    // Output final block
    _checkOpIsOne(ssl.EVP_CipherFinal_ex(ctx, outBuf, outLen));
    if (outLen.value > 0) {
      yield outData.sublist(0, outLen.value);
    }
  } finally {
    scope.release();
  }
}

class _AesCtrSecretKey implements AesCtrSecretKey {
  final Uint8List _key;
  _AesCtrSecretKey(this._key);

  void _checkArguments(
    List<int> counter,
    int length,
  ) {
    ArgumentError.checkNotNull(counter, 'counter');
    ArgumentError.checkNotNull(length, 'length');
    if (counter.length != 16) {
      throw ArgumentError.value(counter, 'counter', 'must be 16 bytes');
    }
    if (length <= 0 || 128 < length) {
      throw ArgumentError.value(length, 'length', 'must be between 1 and 128');
    }
  }

  @override
  Future<Uint8List> decryptBytes(
    List<int> data,
    List<int> counter,
    int length,
  ) async {
    ArgumentError.checkNotNull(data, 'data');
    _checkArguments(counter, length);
    return await _bufferStream(decryptStream(
      Stream.value(data),
      counter,
      length,
    ));
  }

  @override
  Stream<Uint8List> decryptStream(
    Stream<List<int>> data,
    List<int> counter,
    int length,
  ) {
    ArgumentError.checkNotNull(data, 'data');
    _checkArguments(counter, length);
    return _aesCtrEncryptOrDecrypt(_key, false, data, counter, length);
  }

  @override
  Future<Uint8List> encryptBytes(
    List<int> data,
    List<int> counter,
    int length,
  ) async {
    ArgumentError.checkNotNull(data, 'data');
    _checkArguments(counter, length);
    return await _bufferStream(encryptStream(
      Stream.value(data),
      counter,
      length,
    ));
  }

  @override
  Stream<Uint8List> encryptStream(
    Stream<List<int>> data,
    List<int> counter,
    int length,
  ) {
    ArgumentError.checkNotNull(data, 'data');
    _checkArguments(counter, length);
    return _aesCtrEncryptOrDecrypt(_key, true, data, counter, length);
  }

  @override
  Future<Map<String, dynamic>> exportJsonWebKey() async =>
      _aesExportJwkKey(_key, jwkAlgSuffix: 'CTR');

  @override
  Future<Uint8List> exportRawKey() async => Uint8List.fromList(_key);
}
