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

import 'dart:async';
import 'package:js/js_util.dart';
import 'dart:typed_data';
import 'dart:html' show window;
import 'jsonwebkey.dart' show JsonWebKey, RsaOtherPrimesInfo;
export 'jsonwebkey.dart' show JsonWebKey;

/// Constructor for a Javascript `Array`.
final _array = getProperty(window, 'Array');

/// The `window.crypto` object.
final _crypto = getProperty(window, 'crypto');

/// The `window.crypto.subtle` object.
final _subtle = getProperty(_crypto, 'subtle');

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

/// Wrapper for the [CryptoKey][1] type.
///
/// [1]: https://www.w3.org/TR/WebCryptoAPI/#cryptokey-interface
class CryptoKey {
  final Object _jsObj;

  CryptoKey(this._jsObj);

  /// Returns the _type_ of this key, as one of:
  ///  * `'private'`
  ///  * `'public'`
  ///  * `'secret'`
  String get type => getProperty(_jsObj, 'type');

  /// True, if this key can be extracted.
  bool get extractable => getProperty(_jsObj, 'extractable');

  /// Ways in which this key can be used, list of one or more of:
  ///  * `'encrypt'`,
  ///  * `'decrypt'`,
  ///  * `'sign'`,
  ///  * `'verify'`,
  ///  * `'deriveKey'`,
  ///  * `'deriveBits'`,
  ///  * `'wrapKey'`,
  ///  * `'unwrapKey'`.
  List<String> get usages {
    final jsArray = getProperty(_jsObj, 'usages');
    final N = getProperty(jsArray, 'length');

    return List.generate(N, (i) => getProperty(jsArray, i));
  }
}

/// Wrapper for the [CryptoKeyPair][1] type.
///
/// [1]: https://www.w3.org/TR/WebCryptoAPI/#keypair
class CryptoKeyPair {
  final Object _jsObj;
  CryptoKeyPair(this._jsObj);

  CryptoKey get privateKey => CryptoKey(getProperty(_jsObj, 'privateKey'));
  CryptoKey get publicKey => CryptoKey(getProperty(_jsObj, 'publicKey'));
}

/// Wrapper for the [DOMException][1] type.
///
/// [1]: https://webidl.spec.whatwg.org/#idl-DOMException
class DomException implements Exception {
  final Object _jsObj;
  DomException.wrap(this._jsObj);

  String get name => getProperty(_jsObj, 'name');
  String get message => getProperty(_jsObj, 'message');
}

/// Wrap any error thrown in [fn] as [DomException].
Future<T> _wrapDomException<T>(Future<T> Function() fn) async {
  try {
    return await fn();
  } catch (e) {
    throw DomException.wrap(e);
  }
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
  final Object _jsObj;

  String get name => getProperty(_jsObj, 'name');
  int get modulusLength => getProperty(_jsObj, 'modulusLength');
  Uint8List get publicExponent => getProperty(_jsObj, 'publicExponent');
  String get hash => getProperty(_jsObj, 'hash');
  int get saltLength => getProperty(_jsObj, 'saltLength');
  TypedData get label => getProperty(_jsObj, 'label');
  String get namedCurve => getProperty(_jsObj, 'namedCurve');
  CryptoKey get public => CryptoKey(getProperty(_jsObj, 'public'));
  TypedData get counter => getProperty(_jsObj, 'counter');
  int get length => getProperty(_jsObj, 'length');
  TypedData get iv => getProperty(_jsObj, 'iv');
  TypedData get additionalData => getProperty(_jsObj, 'additionalData');
  int get tagLength => getProperty(_jsObj, 'tagLength');
  TypedData get salt => getProperty(_jsObj, 'salt');
  TypedData get info => getProperty(_jsObj, 'info');
  int get iterations => getProperty(_jsObj, 'iterations');

  Algorithm({
    String? name,
    int? modulusLength,
    Uint8List? publicExponent,
    String? hash,
    int? saltLength,
    TypedData? label,
    String? namedCurve,
    CryptoKey? public,
    TypedData? counter,
    int? length,
    TypedData? iv,
    TypedData? additionalData,
    int? tagLength,
    TypedData? salt,
    TypedData? info,
    int? iterations,
  }) : _jsObj = newObject() {
    if (name != null) {
      setProperty(_jsObj, 'name', name);
    }
    if (modulusLength != null) {
      setProperty(_jsObj, 'modulusLength', modulusLength);
    }
    if (publicExponent != null) {
      setProperty(_jsObj, 'publicExponent', publicExponent);
    }
    if (hash != null) {
      setProperty(_jsObj, 'hash', hash);
    }
    if (saltLength != null) {
      setProperty(_jsObj, 'saltLength', saltLength);
    }
    if (label != null) {
      setProperty(_jsObj, 'label', label);
    }
    if (namedCurve != null) {
      setProperty(_jsObj, 'namedCurve', namedCurve);
    }
    if (public != null) {
      setProperty(_jsObj, 'public', public._jsObj);
    }
    if (counter != null) {
      setProperty(_jsObj, 'counter', counter);
    }
    if (length != null) {
      setProperty(_jsObj, 'length', length);
    }
    if (iv != null) {
      setProperty(_jsObj, 'iv', iv);
    }
    if (additionalData != null) {
      setProperty(_jsObj, 'additionalData', additionalData);
    }
    if (tagLength != null) {
      setProperty(_jsObj, 'tagLength', tagLength);
    }
    if (salt != null) {
      setProperty(_jsObj, 'salt', salt);
    }
    if (info != null) {
      setProperty(_jsObj, 'info', info);
    }
    if (iterations != null) {
      setProperty(_jsObj, 'iterations', iterations);
    }
  }
}

/// Create [JsonWebKey] from [jsObj].
JsonWebKey _jsonWebKeyFromJsObj(Object jsObj) {
  final jwk = JsonWebKey();

  if (hasProperty(jsObj, 'kty')) {
    jwk.kty = getProperty(jsObj, 'kty');
  }
  if (hasProperty(jsObj, 'use')) {
    jwk.use = getProperty(jsObj, 'use');
  }
  if (hasProperty(jsObj, 'key_ops')) {
    jwk.key_ops =
        getProperty<List>(jsObj, 'key_ops').map((s) => s as String).toList();
  }
  if (hasProperty(jsObj, 'alg')) {
    jwk.alg = getProperty(jsObj, 'alg');
  }
  if (hasProperty(jsObj, 'ext')) {
    jwk.ext = getProperty(jsObj, 'ext');
  }
  if (hasProperty(jsObj, 'crv')) {
    jwk.crv = getProperty(jsObj, 'crv');
  }
  if (hasProperty(jsObj, 'x')) {
    jwk.x = getProperty(jsObj, 'x');
  }
  if (hasProperty(jsObj, 'y')) {
    jwk.y = getProperty(jsObj, 'y');
  }
  if (hasProperty(jsObj, 'd')) {
    jwk.d = getProperty(jsObj, 'd');
  }
  if (hasProperty(jsObj, 'n')) {
    jwk.n = getProperty(jsObj, 'n');
  }
  if (hasProperty(jsObj, 'e')) {
    jwk.e = getProperty(jsObj, 'e');
  }
  if (hasProperty(jsObj, 'p')) {
    jwk.p = getProperty(jsObj, 'p');
  }
  if (hasProperty(jsObj, 'q')) {
    jwk.q = getProperty(jsObj, 'q');
  }
  if (hasProperty(jsObj, 'dp')) {
    jwk.dp = getProperty(jsObj, 'dp');
  }
  if (hasProperty(jsObj, 'dq')) {
    jwk.dq = getProperty(jsObj, 'dq');
  }
  if (hasProperty(jsObj, 'qi')) {
    jwk.qi = getProperty(jsObj, 'qi');
  }
  if (hasProperty(jsObj, 'oth')) {
    jwk.oth = getProperty<List>(jsObj, 'oth')
        .map((jsObj) => RsaOtherPrimesInfo(
              r: getProperty(jsObj, 'r'),
              d: getProperty(jsObj, 'd'),
              t: getProperty(jsObj, 't'),
            ))
        .toList();
  }
  if (hasProperty(jsObj, 'k')) {
    jwk.k = getProperty(jsObj, 'k');
  }

  return jwk;
}

/// Convert [JsonWebKey] to a javascript object.
Object _jsonWebKeyToJsObj(JsonWebKey jwk) {
  final jsObj = newObject();

  if (jwk.kty != null) {
    setProperty(jsObj, 'kty', jwk.kty);
  }
  if (jwk.use != null) {
    setProperty(jsObj, 'use', jwk.use);
  }
  if (jwk.key_ops != null) {
    setProperty(jsObj, 'key_ops', jwk.key_ops);
  }
  if (jwk.alg != null) {
    setProperty(jsObj, 'alg', jwk.alg);
  }
  if (jwk.ext != null) {
    setProperty(jsObj, 'ext', jwk.ext);
  }
  if (jwk.crv != null) {
    setProperty(jsObj, 'crv', jwk.crv);
  }
  if (jwk.x != null) {
    setProperty(jsObj, 'x', jwk.x);
  }
  if (jwk.y != null) {
    setProperty(jsObj, 'y', jwk.y);
  }
  if (jwk.d != null) {
    setProperty(jsObj, 'd', jwk.d);
  }
  if (jwk.n != null) {
    setProperty(jsObj, 'n', jwk.n);
  }
  if (jwk.e != null) {
    setProperty(jsObj, 'e', jwk.e);
  }
  if (jwk.p != null) {
    setProperty(jsObj, 'p', jwk.p);
  }
  if (jwk.q != null) {
    setProperty(jsObj, 'q', jwk.q);
  }
  if (jwk.dp != null) {
    setProperty(jsObj, 'dp', jwk.dp);
  }
  if (jwk.dq != null) {
    setProperty(jsObj, 'dq', jwk.dq);
  }
  if (jwk.qi != null) {
    setProperty(jsObj, 'qi', jwk.qi);
  }
  final oth = jwk.oth;
  if (oth != null) {
    final jsArray = callConstructor(_array, [
      oth.map((info) {
        final jsObj = newObject();
        setProperty(jsObj, 'r', info.r);
        setProperty(jsObj, 'd', info.d);
        setProperty(jsObj, 't', info.t);
        return jsObj;
      }).toList(),
    ]);
    setProperty(jsObj, 'oth', jsArray);
  }
  if (jwk.k != null) {
    setProperty(jsObj, 'k', jwk.k);
  }

  return jsObj;
}

/// Convert a [list] a Javascript object.
Object _stringListToJsObj(List<String> list) => callConstructor(
      _array,
      list,
    );

TypedData getRandomValues(TypedData array) =>
    callMethod(_crypto, 'getRandomValues', [array]);

Future<ByteBuffer> decrypt(
  Algorithm algorithm,
  CryptoKey key,
  TypedData data,
) =>
    _wrapDomException(() => promiseToFuture(callMethod(_subtle, 'decrypt', [
          algorithm._jsObj,
          key._jsObj,
          data,
        ])));

Future<ByteBuffer> encrypt(
  Algorithm algorithm,
  CryptoKey key,
  TypedData data,
) =>
    _wrapDomException(() => promiseToFuture(callMethod(_subtle, 'encrypt', [
          algorithm._jsObj,
          key._jsObj,
          data,
        ])));

Future<ByteBuffer> exportKey(
  String format,
  CryptoKey key,
) =>
    _wrapDomException(() => promiseToFuture(callMethod(_subtle, 'exportKey', [
          format,
          key._jsObj,
        ])));

Future<JsonWebKey> exportJsonWebKey(
  String format,
  CryptoKey key,
) async =>
    _jsonWebKeyFromJsObj(await _wrapDomException(
      () => promiseToFuture(callMethod(_subtle, 'exportKey', [
        format,
        key._jsObj,
      ])),
    ));

Future<CryptoKey> generateKey(
  Algorithm algorithm,
  bool extractable,
  List<String> usages,
) async =>
    CryptoKey(await _wrapDomException(
      () => promiseToFuture(callMethod(_subtle, 'generateKey', [
        algorithm._jsObj,
        extractable,
        _stringListToJsObj(usages),
      ])),
    ));

Future<CryptoKeyPair> generateKeyPair(
  Algorithm algorithm,
  bool extractable,
  List<String> usages,
) async =>
    CryptoKeyPair(await _wrapDomException(
      () => promiseToFuture(callMethod(_subtle, 'generateKey', [
        algorithm._jsObj,
        extractable,
        _stringListToJsObj(usages),
      ])),
    ));

Future<ByteBuffer> digest(String algorithm, TypedData data) =>
    _wrapDomException(() => promiseToFuture(callMethod(_subtle, 'digest', [
          algorithm,
          data,
        ])));

Future<CryptoKey> importKey(
  String format,
  TypedData keyData,
  Algorithm algorithm,
  bool extractable,
  List<String> usages,
) async =>
    CryptoKey(await _wrapDomException(
      () => promiseToFuture(callMethod(_subtle, 'importKey', [
        format,
        keyData,
        algorithm._jsObj,
        extractable,
        _stringListToJsObj(usages),
      ])),
    ));

Future<CryptoKey> importJsonWebKey(
  String format,
  JsonWebKey jwk,
  Algorithm algorithm,
  bool extractable,
  List<String> usages,
) async =>
    CryptoKey(await _wrapDomException(
      () => promiseToFuture(callMethod(_subtle, 'importKey', [
        format,
        _jsonWebKeyToJsObj(jwk),
        algorithm._jsObj,
        extractable,
        _stringListToJsObj(usages),
      ])),
    ));

Future<ByteBuffer> sign(
  Algorithm algorithm,
  CryptoKey key,
  TypedData data,
) =>
    _wrapDomException(() => promiseToFuture(callMethod(_subtle, 'sign', [
          algorithm._jsObj,
          key._jsObj,
          data,
        ])));

Future<bool> verify(
  Algorithm algorithm,
  CryptoKey key,
  TypedData signature,
  TypedData data,
) =>
    _wrapDomException(() => promiseToFuture(callMethod(_subtle, 'verify', [
          algorithm._jsObj,
          key._jsObj,
          signature,
          data,
        ])));

Future<ByteBuffer> deriveBits(
  Algorithm algorithm,
  CryptoKey key,
  int length,
) =>
    _wrapDomException(() => promiseToFuture(callMethod(_subtle, 'deriveBits', [
          algorithm._jsObj,
          key._jsObj,
          length,
        ])));

// TODO: crypto.subtle.unwrapKey
// TODO: crypto.subtle.wrapKey
// TODO: crypto.subtle.deriveKey
