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

part of 'impl_jni.dart';

void _checkData(bool condition, String message) {
  if (!condition) {
    throw FormatException(message);
  }
}

Uint8List _asUint8ListZeroedToBitLength(List<int> data, [int? lengthInBits]) {
  final bytes = Uint8List.fromList(data);
  if (lengthInBits == null) {
    return bytes;
  }

  final startFrom = lengthInBits ~/ 8;
  var remainder = lengthInBits % 8;
  for (var i = startFrom; i < bytes.length; i++) {
    final mask = 0xff & (0xff << (8 - remainder));
    bytes[i] = bytes[i] & mask;
    remainder = 8;
  }
  return bytes;
}

Uint8List _jwkDecodeBase64UrlNoPadding(String unpadded, String prop) {
  try {
    final padded = unpadded.padRight(
      unpadded.length + ((4 - (unpadded.length % 4)) % 4),
      '=',
    );
    return base64Url.decode(padded);
  } on FormatException {
    throw FormatException(
      'JWK property "$prop" is not url-safe base64 without padding',
      unpadded,
    );
  }
}

String _jwkEncodeBase64UrlNoPadding(Uint8List data) {
  final padded = base64Url.encode(data);
  final paddingStart = padded.indexOf('=');
  return paddingStart == -1 ? padded : padded.substring(0, paddingStart);
}

extension _JniArenaByteArray on jni.Arena {
  jni.JByteArray copyToJByteArray(Iterable<int> data) {
    return jni.JByteArray.of(data)..releasedBy(this);
  }
}

extension _JByteArrayCopy on jni.JByteArray {
  /// Copies this JVM byte array into Dart-owned memory.
  Uint8List copyToDartBytes() {
    final bytes = getRange(0, length);
    final view = bytes.buffer.asUint8List(bytes.offsetInBytes, bytes.length);
    return Uint8List.fromList(view);
  }
}

Uint8List _randomBytes(int length) {
  final output = Uint8List(length);
  _fillRandomBytes(output);
  return output;
}

void _fillRandomBytes(TypedData destination) {
  final output = destination.buffer.asUint8List(
    destination.offsetInBytes,
    destination.lengthInBytes,
  );
  if (output.isEmpty) {
    return;
  }

  jni.using((arena) {
    final random = SecureRandom()..releasedBy(arena);
    final bufferLength = output.length < 4096 ? output.length : 4096;
    final bytes = jni.JByteArray(bufferLength)..releasedBy(arena);

    var offset = 0;
    while (offset < output.length) {
      random.nextBytes(bytes);
      final remaining = output.length - offset;
      final chunkLength = remaining < bufferLength ? remaining : bufferLength;
      output.setRange(offset, offset + chunkLength, bytes.copyToDartBytes());
      offset += chunkLength;
    }
  });
}
