import 'dart:typed_data';
import 'package:webcrypto/webcrypto.dart';

void log(Object value) => print(value);

void check(bool condition, [String message]) {
  if (!condition) {
    throw AssertionError(message);
  }
}

Hash hashFromJson(dynamic json) {
  if (json is Map) {
    json = json['hash'];
  }
  if (json == 'sha-1') {
    return Hash.sha1;
  }
  if (json == 'sha-256') {
    return Hash.sha256;
  }
  if (json == 'sha-384') {
    return Hash.sha384;
  }
  if (json == 'sha-512') {
    return Hash.sha512;
  }
  check(false, 'invalid hash specification');
  return null; // unreachable
}

String hashToJson(Hash h) {
  if (h == Hash.sha1) {
    return 'sha-1';
  }
  if (h == Hash.sha256) {
    return 'sha-256';
  }
  if (h == Hash.sha384) {
    return 'sha-384';
  }
  if (h == Hash.sha512) {
    return 'sha-512';
  }
  check(false, 'invalid hash implementation');
  return null; // unreachable
}

/// Flip the first bit of every byte
///
/// Useful for generating an invalidate signature.
Uint8List flipFirstBits(List<int> data) =>
    Uint8List.fromList(data.map((i) => i ^ 0x1).toList());
