import 'dart:typed_data';
import 'package:webcrypto/webcrypto.dart';
import 'package:test/test.dart';

void log(Object value) => print(value);

void check(bool condition, [String message]) {
  if (!condition) {
    fail(message);
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

String curveToJson(EllipticCurve curve) {
  if (curve == EllipticCurve.p256) {
    return 'p-256';
  }
  if (curve == EllipticCurve.p384) {
    return 'p-384';
  }
  if (curve == EllipticCurve.p521) {
    return 'p-521';
  }
  check(false, 'invalid curve implementation');
  return null; // unreachable
}

EllipticCurve curveFromJson(dynamic json) {
  if (json is Map) {
    json = json['curve'];
  }
  if (json == 'p-256') {
    return EllipticCurve.p256;
  }
  if (json == 'p-384') {
    return EllipticCurve.p384;
  }
  if (json == 'p-521') {
    return EllipticCurve.p521;
  }
  check(false, 'invalid curve specification');
  return null; // unreachable
}

/// Flip the first bit of every byte
///
/// Useful for generating an invalidate signature.
Uint8List flipFirstBits(List<int> data) =>
    Uint8List.fromList(data.map((i) => i ^ 0x1).toList());
