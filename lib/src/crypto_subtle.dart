/// This library attempts to expose the definitions necessary to use the
/// browsers `window.crypto.subtle` APIs.
@JS()
library common;

import 'dart:async';
import 'package:js/js.dart';
import 'dart:typed_data';
import 'dart:html' show DomException;
export 'dart:html' show DomException;

/// Minimal interface for promises as returned from the browsers WebCrypto API.
@JS('Promise')
class Promise<T> {
  external Promise then(
      void Function(T) onAccept, void Function(DomException) onReject);
}

/// Convert a promise to a future.
Future<T> promiseAsFuture<T>(Promise<T> promise) {
  ArgumentError.checkNotNull(promise, 'promise');

  final c = Completer<T>();
  promise.then(allowInterop(Zone.current.bindUnaryCallback((T result) {
    c.complete(result);
  })), allowInterop(Zone.current.bindUnaryCallback((DomException e) {
    c.completeError(e);
  })));
  return c.future;
}

/// Convert [BigInt] to [Uint8List] formatted as [BigInteger][1] following
/// the Web Cryptography specification.
///
/// [1]: https://www.w3.org/TR/WebCryptoAPI/#big-integer
Uint8List bigIntToUint8ListBigInteger(BigInt integer) {
  if (integer == BigInt.from(65537)) {
    return Uint8List.fromList([0x01, 0x00, 0x01]); // 65537
  }
  if (integer == BigInt.from(3)) {
    return Uint8List.fromList([0x03]); // 3
  }

  // TODO: Implement bigIntToUint8ListBigInteger for all positive integers
  // There is no rush as this is only used for public exponent, and chrome only
  // supports 3 and 65537, so supporting other numbers is a low priority.
  // https://chromium.googlesource.com/chromium/src/+/43d62c50b705f88c67b14539e91fd8fd017f70c4/components/webcrypto/algorithms/rsa.cc#286
  throw UnimplementedError('Only supports 65537 and 3 for now');
}

/// Minimal interface for the CryptoKey type.
@JS('CryptoKey')
class CryptoKey {
  /// Returns the _type_ of this key, as one of:
  ///  * `'private'`
  ///  * `'public'`
  ///  * `'secret'`
  external String get type;

  /// True, if this key can be extracted.
  external bool get extractable;

  /// Ways in which this key can be used, list of one or more of:
  ///  * `'encrypt'`,
  ///  * `'decrypt'`,
  ///  * `'sign'`,
  ///  * `'verify'`,
  ///  * `'deriveKey'`,
  ///  * `'deriveBits'`,
  ///  * `'wrapKey'`,
  ///  * `'unwrapKey'`.
  external List<String> get usages;
}

/// Interface for the [CryptoKeyPair][1].
///
/// [1]: https://www.w3.org/TR/WebCryptoAPI/#keypair
@JS('CryptoKeyPair')
class CryptoKeyPair {
  external CryptoKey get privateKey;
  external CryptoKey get publicKey;
}

/// Anonymous object to be used for constructing the `algorithm` parameter in
/// `subtle.crypto` methods.
///
/// Note this only works because [WebIDL specification][1] for converting
/// dictionaries say to ignore properties whose values are `null` or
/// `undefined`. Otherwise, this object would define a lot of properties that
/// are not permitted. If two parameters for any algorithms in the Web
/// Cryptography specification has conflicting tyoes in the future, we might
/// have to split this into multiple types. But so they don't have conflicting
/// parameters there is no reason to make a type per algorithm.
///
/// [1]: https://www.w3.org/TR/WebIDL-1/#es-dictionary
@JS()
@anonymous
class Algorithm {
  external String get name;
  external int get modulusLength;
  external Uint8List get publicExponent;
  external String get hash;
  external int get saltLength;
  external TypedData get label;
  external String get namedCurve;
  external CryptoKey get public;
  external TypedData get counter;
  external int get length;
  external TypedData get iv;
  external TypedData get additionalData;
  external int get tagLength;
  external TypedData get salt;
  external TypedData get info;
  external int get iterations;

  external factory Algorithm({
    String name,
    int modulusLength,
    Uint8List publicExponent,
    String hash,
    int saltLength,
    TypedData label,
    String namedCurve,
    CryptoKey public,
    TypedData counter,
    int length,
    TypedData iv,
    TypedData additionalData,
    int tagLength,
    TypedData salt,
    TypedData info,
    int iterations,
  });
}

/// Interface for the [JsonWebKey dictionary][1].
///
/// See also list of [registered parameters][2].
///
/// [1]: https://www.w3.org/TR/WebCryptoAPI/#JsonWebKey-dictionary
/// [2]: https://www.iana.org/assignments/jose/jose.xhtml#web-key-parameters
@JS()
@anonymous
class JsonWebKey {
  external String get kty;
  external String get use;
  external List<String> get key_ops;
  external String get alg;
  external bool get ext;
  external String get crv;
  external String get x;
  external String get y;
  external String get d;
  external String get n;
  external String get e;
  external String get p;
  external String get q;
  external String get dp;
  external String get dq;
  external String get qi;
  external List<RsaOtherPrimesInfo> get oth;
  external String get k;

  external factory JsonWebKey({
    String kty,
    String use,
    List<String> key_ops,
    String alg,
    bool ext,
    String crv,
    String x,
    String y,
    String d,
    String n,
    String e,
    String p,
    String q,
    String dp,
    String dq,
    String qi,
    List<RsaOtherPrimesInfo> oth,
    String k,
  });

  static JsonWebKey fromJson(Map<String, Object> json) {
    const stringKeys = [
      'kty',
      'use',
      'alg',
      'crv',
      'x',
      'y',
      'd',
      'n',
      'e',
      'p',
      'q',
      'dp',
      'dq',
      'qi',
      'k',
    ];
    for (final k in stringKeys) {
      if (json.containsKey(k) && !(json[k] is String)) {
        throw ArgumentError('JWK entry "$k" must be a string');
      }
    }
    if (json.containsKey('key_ops') && !(json['key_ops'] is List<String>)) {
      throw ArgumentError('JWK entry "key_ops" must be a list of strings');
    }
    if (json.containsKey('ext') && !(json['ext'] is bool)) {
      throw ArgumentError('JWK entry "ext" must be boolean');
    }
    List<RsaOtherPrimesInfo> oth;
    if (json.containsKey('oth')) {
      if (!(json['oth'] is List<Map<String, Object>>)) {
        throw ArgumentError('JWK entry "oth" must be list of maps');
      }
      oth = (json['oth'] as List<Map<String, Object>>).map((json) {
        return RsaOtherPrimesInfo.fromJson(json);
      });
    }
    return JsonWebKey(
      kty: json['kty'] as String,
      use: json['use'] as String,
      key_ops: json['key_ops'] as List<String>,
      alg: json['alg'] as String,
      ext: json['ext'] as bool,
      crv: json['crv'] as String,
      x: json['x'] as String,
      y: json['y'] as String,
      d: json['d'] as String,
      n: json['n'] as String,
      e: json['e'] as String,
      p: json['p'] as String,
      q: json['q'] as String,
      dp: json['dp'] as String,
      dq: json['dq'] as String,
      qi: json['qi'] as String,
      oth: oth,
      k: json['k'] as String,
    );
  }

  static Map<String, Object> toJson(JsonWebKey k) {
    assert(k != null);
    final json = <String, Object>{};

    // Set properties from all the string keys
    if (k.kty != null) {
      json['kty'] = k.kty;
    }
    if (k.use != null) {
      json['use'] = k.use;
    }
    if (k.alg != null) {
      json['alg'] = k.alg;
    }
    if (k.crv != null) {
      json['crv'] = k.crv;
    }
    if (k.x != null) {
      json['x'] = k.x;
    }
    if (k.y != null) {
      json['y'] = k.y;
    }
    if (k.d != null) {
      json['d'] = k.d;
    }
    if (k.n != null) {
      json['n'] = k.n;
    }
    if (k.e != null) {
      json['e'] = k.e;
    }
    if (k.p != null) {
      json['p'] = k.p;
    }
    if (k.q != null) {
      json['q'] = k.q;
    }
    if (k.dp != null) {
      json['dp'] = k.dp;
    }
    if (k.dq != null) {
      json['dq'] = k.dq;
    }
    if (k.qi != null) {
      json['qi'] = k.qi;
    }
    if (k.k != null) {
      json['k'] = k.k;
    }

    // Set non-string properties
    if (k.key_ops != null) {
      json['key_ops'] = k.key_ops;
    }
    if (k.ext != null) {
      json['ext'] = k.ext;
    }
    if (k.oth != null) {
      json['oth'] = k.oth.map(RsaOtherPrimesInfo.toJson);
    }

    return json;
  }
}

/// Interface for `RsaOtherPrimesInfo` used in the [JsonWebKey dictionary][1].
///
/// See also "oth" in [RFC 7518 Section 6.3.2.7].
///
/// [1]: https://www.w3.org/TR/WebCryptoAPI/#JsonWebKey-dictionary
/// [2]: https://tools.ietf.org/html/rfc7518#section-6.3.2.7
@JS()
@anonymous
class RsaOtherPrimesInfo {
  external String get r;
  external String get d;
  external String get t;

  external factory RsaOtherPrimesInfo({
    String r,
    String d,
    String t,
  });

  static RsaOtherPrimesInfo fromJson(Map<String, Object> json) {
    for (final k in ['r', 'd', 't']) {
      if (!(json[k] is String)) {
        throw ArgumentError('"oth" entries in a JWK must contain "$k"');
      }
    }
    return RsaOtherPrimesInfo(
      r: json['r'] as String,
      d: json['d'] as String,
      t: json['t'] as String,
    );
  }

  static Map<String, Object> toJson(RsaOtherPrimesInfo info) {
    assert(info != null);
    return <String, Object>{
      'r': info.r,
      'd': info.d,
      't': info.t,
    };
  }
}

@JS('crypto.getRandomValues')
external Promise<ByteBuffer> getRandomValues(TypedData array);

@JS('crypto.subtle.decrypt')
external Promise<ByteBuffer> decrypt(
  Algorithm algorithm,
  CryptoKey key,
  TypedData data,
);

@JS('crypto.subtle.encrypt')
external Promise<ByteBuffer> encrypt(
  Algorithm algorithm,
  CryptoKey key,
  TypedData data,
);

@JS('crypto.subtle.exportKey')
external Promise<ByteBuffer> exportKey(
  String format,
  CryptoKey key,
);

@JS('crypto.subtle.exportKey')
external Promise<JsonWebKey> exportJsonWebKey(
  String format,
  CryptoKey key,
);

@JS('crypto.subtle.generateKey')
external Promise<CryptoKey> generateKey(
  Algorithm algorithm,
  bool extractable,
  List<String> usages,
);

@JS('crypto.subtle.generateKey')
external Promise<CryptoKeyPair> generateKeyPair(
  Algorithm algorithm,
  bool extractable,
  List<String> usages,
);

@JS('crypto.subtle.digest')
external Promise<ByteBuffer> digest(String algorithm, TypedData data);

@JS('crypto.subtle.importKey')
external Promise<CryptoKey> importKey(
  String format,
  TypedData keyData,
  Algorithm algorithm,
  bool extractable,
  List<String> usages,
);

@JS('crypto.subtle.import')
external Promise<CryptoKey> importJsonWebKey(
  String format,
  JsonWebKey jwk,
  Algorithm algorithm,
  bool extractable,
  List<String> usages,
);

@JS('crypto.subtle.sign')
external Promise<ByteBuffer> sign(
  Algorithm algorithm,
  CryptoKey key,
  TypedData data,
);

@JS('crypto.subtle.verify')
external Promise<bool> verify(
  Algorithm algorithm,
  CryptoKey key,
  TypedData signature,
  TypedData data,
);

@JS('crypto.subtle.deriveBits')
external Promise<ByteBuffer> deriveBits(
  Algorithm algorithm,
  CryptoKey key,
  int length,
);

// TODO: crypto.subtle.unwrapKey
// TODO: crypto.subtle.wrapKey
// TODO: crypto.subtle.deriveKey
