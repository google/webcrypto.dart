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

/// This library attempts to expose the definitions necessary to use the
/// browsers `window.crypto.subtle` APIs.
library common;

import 'dart:js_interop';
import 'dart:typed_data';

import 'package:meta/meta.dart';

import 'jsonwebkey.dart' show JsonWebKey, RsaOtherPrimesInfo;

export 'jsonwebkey.dart' show JsonWebKey;

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

/// The `window` object.
@JS()
external JSWindow get window;

/// https://developer.mozilla.org/en-US/docs/Web/API/Window
extension type JSWindow(JSObject _) implements JSObject {
  /// https://developer.mozilla.org/en-US/docs/Web/API/crypto_property
  external JSCrypto get crypto;
}

/// The `window.crypto` object.
///
/// https://www.w3.org/TR/WebCryptoAPI/#crypto-interface
/// https://developer.mozilla.org/en-US/docs/Web/API/Crypto
extension type JSCrypto(JSObject _) implements JSObject {
  /// https://developer.mozilla.org/en-US/docs/Web/API/Crypto/subtle
  external JSSubtleCrypto get subtle;

  /// https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues
  external JSTypedArray getRandomValues(JSTypedArray array);
}

/// The `window.crypto.subtle` object.
///
/// https://www.w3.org/TR/WebCryptoAPI/#subtlecrypto-interface
/// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
extension type JSSubtleCrypto(JSObject _) implements JSObject {
  /// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt
  external JSPromise<JSArrayBuffer> encrypt(
    JSAny algorithm,
    JSCryptoKey key,
    JSTypedArray data,
  );

  /// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/decrypt
  external JSPromise<JSArrayBuffer> decrypt(
    JSAny algorithm,
    JSAny key,
    JSTypedArray data,
  );

  /// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/sign
  external JSPromise<JSArrayBuffer> sign(
    JSAny algorithm,
    JSCryptoKey key,
    JSTypedArray data,
  );

  /// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/verify
  external JSPromise<JSBoolean> verify(
    JSAny algorithm,
    JSCryptoKey key,
    JSTypedArray signature,
    JSTypedArray data,
  );

  /// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest
  external JSPromise<JSArrayBuffer> digest(String algorithm, JSTypedArray data);

  /// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveBits
  external JSPromise<JSArrayBuffer> deriveBits(
    JSAny algorithm,
    JSCryptoKey baseKey,
    int length,
  );

  /// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey
  @JS('generateKey')
  external JSPromise<JSCryptoKey> generateCryptoKey(
    JSAny algorithm,
    bool extractable,
    JSArray<JSString> keyUsages,
  );

  /// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey
  @JS('generateKey')
  external JSPromise<JSCryptoKeyPair> generateCryptoKeyPair(
    JSAny algorithm,
    bool extractable,
    JSArray<JSString> keyUsages,
  );

  /// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey
  @JS('importKey')
  external JSPromise<JSCryptoKey> importKey(
    String format,
    JSTypedArray keyData,
    JSAny algorithm,
    bool extractable,
    JSArray<JSString> keyUsages,
  );

  /// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey
  @JS('importKey')
  external JSPromise<JSCryptoKey> importJsonWebKey(
    String format,
    JSAny keyData,
    JSAny algorithm,
    bool extractable,
    JSArray<JSString> keyUsages,
  );

  /// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/exportKey
  @JS('exportKey')
  external JSPromise<JSArrayBuffer> exportKey(String format, JSCryptoKey key);

  /// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/exportKey
  @JS('exportKey')
  external JSPromise<JSJsonWebKey> exportJsonWebKey(
    String format,
    JSCryptoKey key,
  );
}

/// Wrapper for the [CryptoKey][1] type.
///
/// [1]: https://www.w3.org/TR/WebCryptoAPI/#cryptokey-interface
/// https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey
extension type JSCryptoKey(JSObject _) implements JSObject {
  /// Returns the _type_ of this key, as one of:
  ///  * `'private'`
  ///  * `'public'`
  ///  * `'secret'`
  ///
  /// https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey/type
  external String get type;

  /// True, if this key can be extracted.
  ///
  /// https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey/extractable
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
  ///
  /// https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey/usages
  external JSArray<JSString> get usages;
}

/// Wrapper for the [CryptoKeyPair][1] type.
///
/// [1]: https://www.w3.org/TR/WebCryptoAPI/#keypair
/// https://developer.mozilla.org/en-US/docs/Web/API/CryptoKeyPair
extension type JSCryptoKeyPair(JSObject _) implements JSObject {
  /// https://developer.mozilla.org/en-US/docs/Web/API/CryptoKeyPair#cryptokeypair.privatekey
  external JSCryptoKey get privateKey;

  /// https://developer.mozilla.org/en-US/docs/Web/API/CryptoKeyPair#cryptokeypair.publickey
  external JSCryptoKey get publicKey;
}

/// Wrapper for the [DOMException][1] type.
///
/// [1]: https://webidl.spec.whatwg.org/#idl-DOMException
@JS('DOMException')
extension type JSDomException(JSObject _) implements JSObject {
  external String get name;
  external String get message;
}

/// Anonymous object to be used for constructing the `algorithm` parameter in
/// `subtle.crypto` methods.
///
/// Note this only works because [WebIDL specification][1] for converting
/// dictionaries say to ignore properties whose values are `null` or
/// `undefined`. Otherwise, this object would define a lot of properties that
/// are not permitted. If two parameters for any algorithms in the Web
/// Cryptography specification has conflicting types in the future, we might
/// have to split this into multiple types. But so long as they don't have
/// conflicting parameters there is no reason to make a type per algorithm.
///
/// [1]: https://www.w3.org/TR/WebIDL-1/#es-dictionary
class Algorithm {
  const Algorithm({
    this.name,
    this.modulusLength,
    this.publicExponent,
    this.hash,
    this.saltLength,
    this.label,
    this.namedCurve,
    this.public,
    this.counter,
    this.length,
    this.iv,
    this.additionalData,
    this.tagLength,
    this.salt,
    this.info,
    this.iterations,
  });

  final String? name;
  final int? modulusLength;
  final Uint8List? publicExponent;
  final String? hash;
  final int? saltLength;
  final TypedData? label;
  final String? namedCurve;
  final JSCryptoKey? public;
  final TypedData? counter;
  final int? length;
  final TypedData? iv;
  final TypedData? additionalData;
  final int? tagLength;
  final TypedData? salt;
  final TypedData? info;
  final int? iterations;

  Algorithm update({
    String? name,
    int? modulusLength,
    Uint8List? publicExponent,
    String? hash,
    int? saltLength,
    TypedData? label,
    String? namedCurve,
    JSCryptoKey? public,
    TypedData? counter,
    int? length,
    TypedData? iv,
    TypedData? additionalData,
    int? tagLength,
    TypedData? salt,
    TypedData? info,
    int? iterations,
  }) => Algorithm(
    name: this.name ?? name,
    modulusLength: this.modulusLength ?? modulusLength,
    publicExponent: this.publicExponent ?? publicExponent,
    hash: this.hash ?? hash,
    saltLength: this.saltLength ?? saltLength,
    label: this.label ?? label,
    namedCurve: this.namedCurve ?? namedCurve,
    public: this.public ?? public,
    counter: this.counter ?? counter,
    length: this.length ?? length,
    iv: this.iv ?? iv,
    additionalData: this.additionalData ?? additionalData,
    tagLength: this.tagLength ?? tagLength,
    salt: this.salt ?? salt,
    info: this.info ?? info,
    iterations: this.iterations ?? iterations,
  );
}

extension type JSJsonWebKey(JSObject _) implements JSObject {
  external String? get kty;
  external String? get use;
  @JS('key_ops')
  external JSArray<JSString>? get keyOps;
  external String? get alg;
  external bool? get ext;
  external String? get crv;
  external String? get x;
  external String? get y;
  external String? get d;
  external String? get n;
  external String? get e;
  external String? get p;
  external String? get q;
  external String? get dp;
  external String? get dq;
  external String? get qi;
  external JSArray<JSRsaOtherPrimesInfo>? get oth;
  external String? get k;
}

extension type JSRsaOtherPrimesInfo(JSObject _) implements JSObject {
  external String get r;
  external String get d;
  external String get t;
}

TypedData getRandomValues(TypedData array) {
  // The `.toJS` on `Uint8List` (and friends) may:
  //   * cast,
  //   * create a wrapper, or,
  //   * clone.
  // See: https://api.dart.dev/dart-js_interop/Uint8ListToJSUint8Array/toJS.html
  //
  // Thus, when we do `.toJS` and pass the resulting object to `getRandomValues`,
  // we don't know if `.toJS` simply cast or created a wrapper such that changes
  // made by `getRandomBytes` are reflected in `array`.
  //
  // For this reason, we must use `.setAll` to copy the values into `array`, if it
  // was not cast.
  //
  // See also: https://github.com/dart-lang/sdk/issues/59651
  if (array is Uint8List) {
    final jsArray = array.toJS;
    window.crypto.getRandomValues(jsArray);
    final dartArray = jsArray.toDart;
    if (array != dartArray) {
      array.setAll(0, dartArray);
    }
  } else if (array is Uint16List) {
    final jsArray = array.toJS;
    window.crypto.getRandomValues(jsArray);
    final dartArray = jsArray.toDart;
    if (array != dartArray) {
      array.setAll(0, dartArray);
    }
  } else if (array is Uint32List) {
    final jsArray = array.toJS;
    window.crypto.getRandomValues(jsArray);
    final dartArray = jsArray.toDart;
    if (array != dartArray) {
      array.setAll(0, dartArray);
    }
  } else if (array is Int8List) {
    final jsArray = array.toJS;
    window.crypto.getRandomValues(jsArray);
    final dartArray = jsArray.toDart;
    if (array != dartArray) {
      array.setAll(0, dartArray);
    }
  } else if (array is Int16List) {
    final jsArray = array.toJS;
    window.crypto.getRandomValues(jsArray);
    final dartArray = jsArray.toDart;
    if (array != dartArray) {
      array.setAll(0, dartArray);
    }
  } else if (array is Int32List) {
    final jsArray = array.toJS;
    window.crypto.getRandomValues(jsArray);
    final dartArray = jsArray.toDart;
    if (array != dartArray) {
      array.setAll(0, dartArray);
    }
  } else {
    throw ArgumentError.value(array, 'array', 'Unsupported TypedData type');
  }

  return array;
}

Future<ByteBuffer> decrypt(
  Algorithm algorithm,
  JSCryptoKey key,
  Uint8List data,
) async {
  final value = await window.crypto.subtle
      .decrypt(algorithm.toJS, key, data.toJS)
      .toDart;

  return value.toDart;
}

Future<ByteBuffer> encrypt(
  Algorithm algorithm,
  JSCryptoKey key,
  Uint8List data,
) async {
  final value = await window.crypto.subtle
      .encrypt(algorithm.toJS, key, data.toJS)
      .toDart;

  return value.toDart;
}

Future<ByteBuffer> exportKey(String format, JSCryptoKey key) async {
  final value = await window.crypto.subtle.exportKey(format, key).toDart;

  return value.toDart;
}

Future<JsonWebKey> exportJsonWebKey(String format, JSCryptoKey key) async {
  final value = await window.crypto.subtle.exportJsonWebKey(format, key).toDart;

  return value.toDart;
}

Future<JSCryptoKey> generateKey(
  Algorithm algorithm,
  bool extractable,
  List<String> usages,
) async {
  final value = await window.crypto.subtle
      .generateCryptoKey(algorithm.toJS, extractable, usages.toJS)
      .toDart;

  return value;
}

Future<JSCryptoKeyPair> generateKeyPair(
  Algorithm algorithm,
  bool extractable,
  List<String> usages,
) async {
  final value = await window.crypto.subtle
      .generateCryptoKeyPair(algorithm.toJS, extractable, usages.toJS)
      .toDart;

  return value;
}

Future<ByteBuffer> digest(String algorithm, Uint8List data) async {
  final value = await window.crypto.subtle.digest(algorithm, data.toJS).toDart;

  return value.toDart;
}

Future<JSCryptoKey> importKey(
  String format,
  Uint8List keyData,
  Algorithm algorithm,
  bool extractable,
  List<String> usages,
) async {
  final value = await window.crypto.subtle
      .importKey(format, keyData.toJS, algorithm.toJS, extractable, usages.toJS)
      .toDart;

  return value;
}

Future<JSCryptoKey> importJsonWebKey(
  String format,
  JsonWebKey jwk,
  Algorithm algorithm,
  bool extractable,
  List<String> usages,
) async {
  final value = await window.crypto.subtle
      .importJsonWebKey(
        format,
        jwk.toJS,
        algorithm.toJS,
        extractable,
        usages.toJS,
      )
      .toDart;

  return value;
}

Future<ByteBuffer> sign(
  Algorithm algorithm,
  JSCryptoKey key,
  Uint8List data,
) async {
  final value = await window.crypto.subtle
      .sign(algorithm.toJS, key, data.toJS)
      .toDart;

  return value.toDart;
}

Future<bool> verify(
  Algorithm algorithm,
  JSCryptoKey key,
  Uint8List signature,
  Uint8List data,
) async {
  final value = await window.crypto.subtle
      .verify(algorithm.toJS, key, signature.toJS, data.toJS)
      .toDart;

  return value.toDart;
}

Future<ByteBuffer> deriveBits(
  Algorithm algorithm,
  JSCryptoKey key,
  int length,
) async {
  final value = await window.crypto.subtle
      .deriveBits(algorithm.toJS, key, length)
      .toDart;

  return value.toDart;
}

extension ListExtension on List<String> {
  @visibleForTesting
  JSArray<JSString> get toJS =>
      <JSString>[for (final value in this) value.toJS].toJS;
}

extension AlgorithmExtension on Algorithm {
  /// Create JSON from [Algorithm].
  /// To avoid null properties for keys, eliminate keys whose value is null.
  @visibleForTesting
  JSAny get toJS {
    final json = <String, Object>{};
    final name_ = name;
    if (name_ != null) {
      json['name'] = name_;
    }
    final modulusLength_ = modulusLength;
    if (modulusLength_ != null) {
      json['modulusLength'] = modulusLength_;
    }
    final publicExponent_ = publicExponent;
    if (publicExponent_ != null) {
      json['publicExponent'] = publicExponent_;
    }
    final hash_ = hash;
    if (hash_ != null) {
      json['hash'] = hash_;
    }
    final saltLength_ = saltLength;
    if (saltLength_ != null) {
      json['saltLength'] = saltLength_;
    }
    final label_ = label;
    if (label_ != null) {
      json['label'] = label_.buffer;
    }
    final namedCurve_ = namedCurve;
    if (namedCurve_ != null) {
      json['namedCurve'] = namedCurve_;
    }
    final public_ = public;
    if (public_ != null) {
      json['public'] = public_;
    }
    final counter_ = counter;
    if (counter_ != null) {
      json['counter'] = counter_;
    }
    final length_ = length;
    if (length_ != null) {
      json['length'] = length_;
    }
    final iv_ = iv;
    if (iv_ != null) {
      json['iv'] = iv_.buffer;
    }
    final additionalData_ = additionalData;
    if (additionalData_ != null) {
      json['additionalData'] = additionalData_.buffer;
    }
    final tagLength_ = tagLength;
    if (tagLength_ != null) {
      json['tagLength'] = tagLength_;
    }
    final salt_ = salt;
    if (salt_ != null) {
      json['salt'] = salt_.buffer;
    }
    final info_ = info;
    if (info_ != null) {
      json['info'] = info_.buffer;
    }
    final iterations_ = iterations;
    if (iterations_ != null) {
      json['iterations'] = iterations_;
    }

    return json.jsify()!;
  }
}

extension on JsonWebKey {
  /// Create JSON from [JsonWebKey].
  /// Convert the map created by JsonWebKey.toJson(),
  /// to avoid null properties for keys.
  JSAny get toJS => toJson().jsify()!;
}

extension on JSJsonWebKey {
  JsonWebKey get toDart => JsonWebKey(
    kty: kty,
    use: use,
    key_ops: keyOps?.toDart.map((e) => e.toDart).toList(),
    alg: alg,
    ext: ext,
    crv: crv,
    x: x,
    y: y,
    d: d,
    n: n,
    e: e,
    p: p,
    q: q,
    dp: dp,
    dq: dq,
    qi: qi,
    oth: oth?.toDart
        .map((e) => RsaOtherPrimesInfo(r: e.r, d: e.d, t: e.t))
        .toList(),
    k: k,
  );
}

// TODO: crypto.subtle.unwrapKey
// TODO: crypto.subtle.wrapKey
// TODO: crypto.subtle.deriveKey
