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

/// Call [fn] with property [name] from [jsObj], if present.
void _getPropertyIfPresent<T>(Object jsObj, String name, void Function(T) fn) {
  if (hasProperty(jsObj, name)) {
    fn(getProperty(jsObj, name));
  }
}

/// Get property [name] from [jsObj], returns `null` if not present.
T? _getPropertyOrNull<T>(Object jsObj, String name) {
  if (hasProperty(jsObj, name)) {
    return getProperty(jsObj, name);
  }
  return null;
}

/// Set property [name] on [jsObj] if [valie] is not `null`.
void _setPropertyIfPresent<T>(Object jsObj, String name, T? value) {
  if (value != null) {
    setProperty(jsObj, name, value);
  }
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
  List<String> get usages =>
      _jsArrayToListString(getProperty(_jsObj, 'usages'));
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

  String? get name => _getPropertyOrNull(_jsObj, 'name');
  int? get modulusLength => _getPropertyOrNull(_jsObj, 'modulusLength');
  Uint8List? get publicExponent => _getPropertyOrNull(_jsObj, 'publicExponent');
  String? get hash => _getPropertyOrNull(_jsObj, 'hash');
  int? get saltLength => _getPropertyOrNull(_jsObj, 'saltLength');
  TypedData? get label => _getPropertyOrNull(_jsObj, 'label');
  String? get namedCurve => _getPropertyOrNull(_jsObj, 'namedCurve');
  CryptoKey? get public => hasProperty(_jsObj, 'public')
      ? CryptoKey(getProperty(_jsObj, 'public'))
      : null;
  TypedData? get counter => _getPropertyOrNull(_jsObj, 'counter');
  int? get length => _getPropertyOrNull(_jsObj, 'length');
  TypedData? get iv => _getPropertyOrNull(_jsObj, 'iv');
  TypedData? get additionalData => _getPropertyOrNull(_jsObj, 'additionalData');
  int? get tagLength => _getPropertyOrNull(_jsObj, 'tagLength');
  TypedData? get salt => _getPropertyOrNull(_jsObj, 'salt');
  TypedData? get info => _getPropertyOrNull(_jsObj, 'info');
  int? get iterations => _getPropertyOrNull(_jsObj, 'iterations');

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
    _setPropertyIfPresent(_jsObj, 'name', name);
    _setPropertyIfPresent(_jsObj, 'name', name);
    _setPropertyIfPresent(_jsObj, 'modulusLength', modulusLength);
    _setPropertyIfPresent(_jsObj, 'publicExponent', publicExponent);
    _setPropertyIfPresent(_jsObj, 'hash', hash);
    _setPropertyIfPresent(_jsObj, 'saltLength', saltLength);
    _setPropertyIfPresent(_jsObj, 'label', label);
    _setPropertyIfPresent(_jsObj, 'namedCurve', namedCurve);
    if (public != null) {
      setProperty(_jsObj, 'public', public._jsObj);
    }
    _setPropertyIfPresent(_jsObj, 'counter', counter);
    _setPropertyIfPresent(_jsObj, 'length', length);
    _setPropertyIfPresent(_jsObj, 'iv', iv);
    _setPropertyIfPresent(_jsObj, 'additionalData', additionalData);
    _setPropertyIfPresent(_jsObj, 'tagLength', tagLength);
    _setPropertyIfPresent(_jsObj, 'salt', salt);
    _setPropertyIfPresent(_jsObj, 'info', info);
    _setPropertyIfPresent(_jsObj, 'iterations', iterations);
  }

  Algorithm update({
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
  }) =>
      Algorithm(
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

/// Create [JsonWebKey] from [jsObj].
JsonWebKey _jsonWebKeyFromJsObj(Object jsObj) {
  final jwk = JsonWebKey();

  _getPropertyIfPresent(jsObj, 'kty', (String v) => jwk.kty = v);
  _getPropertyIfPresent(jsObj, 'use', (String v) => jwk.use = v);
  _getPropertyIfPresent(
    jsObj,
    'key_ops',
    (Object v) => jwk.key_ops = _jsArrayToListString(v),
  );
  _getPropertyIfPresent(jsObj, 'alg', (String v) => jwk.alg = v);
  _getPropertyIfPresent(jsObj, 'ext', (bool v) => jwk.ext = v);
  _getPropertyIfPresent(jsObj, 'crv', (String v) => jwk.crv = v);
  _getPropertyIfPresent(jsObj, 'x', (String v) => jwk.x = v);
  _getPropertyIfPresent(jsObj, 'y', (String v) => jwk.y = v);
  _getPropertyIfPresent(jsObj, 'd', (String v) => jwk.d = v);
  _getPropertyIfPresent(jsObj, 'n', (String v) => jwk.n = v);
  _getPropertyIfPresent(jsObj, 'e', (String v) => jwk.e = v);
  _getPropertyIfPresent(jsObj, 'p', (String v) => jwk.p = v);
  _getPropertyIfPresent(jsObj, 'q', (String v) => jwk.q = v);
  _getPropertyIfPresent(jsObj, 'dp', (String v) => jwk.dp = v);
  _getPropertyIfPresent(jsObj, 'dq', (String v) => jwk.dq = v);
  _getPropertyIfPresent(jsObj, 'qi', (String v) => jwk.qi = v);
  if (hasProperty(jsObj, 'oth')) {
    final oth = getProperty(jsObj, 'oth');
    final N = getProperty(oth, 'length');
    jwk.oth = List.generate(N, (i) {
      final jsObj = getProperty(oth, i);
      return RsaOtherPrimesInfo(
        r: getProperty(jsObj, 'r'),
        d: getProperty(jsObj, 'd'),
        t: getProperty(jsObj, 't'),
      );
    });
  }
  _getPropertyIfPresent(jsObj, 'k', (String v) => jwk.k = v);

  return jwk;
}

/// Convert [JsonWebKey] to a javascript object.
Object _jsonWebKeyToJsObj(JsonWebKey jwk) {
  final jsObj = newObject();

  _setPropertyIfPresent(jsObj, 'kty', jwk.kty);
  _setPropertyIfPresent(jsObj, 'use', jwk.use);
  _setPropertyIfPresent(jsObj, 'key_ops', jwk.key_ops);
  _setPropertyIfPresent(jsObj, 'alg', jwk.alg);
  _setPropertyIfPresent(jsObj, 'ext', jwk.ext);
  _setPropertyIfPresent(jsObj, 'crv', jwk.crv);
  _setPropertyIfPresent(jsObj, 'x', jwk.x);
  _setPropertyIfPresent(jsObj, 'y', jwk.y);
  _setPropertyIfPresent(jsObj, 'd', jwk.d);
  _setPropertyIfPresent(jsObj, 'n', jwk.n);
  _setPropertyIfPresent(jsObj, 'e', jwk.e);
  _setPropertyIfPresent(jsObj, 'p', jwk.p);
  _setPropertyIfPresent(jsObj, 'q', jwk.q);
  _setPropertyIfPresent(jsObj, 'dp', jwk.dp);
  _setPropertyIfPresent(jsObj, 'dq', jwk.dq);
  _setPropertyIfPresent(jsObj, 'qi', jwk.qi);
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
  _setPropertyIfPresent(jsObj, 'k', jwk.k);

  return jsObj;
}

/// Convert a [list] a Javascript object.
Object _stringListToJsObj(List<String> list) => callConstructor(
      _array,
      list,
    );

/// Convert [jsArray] to [List<String>].
List<String> _jsArrayToListString(Object jsArray) {
  final N = getProperty(jsArray, 'length');
  return List.generate(N, (i) => getProperty(jsArray, i));
}

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
