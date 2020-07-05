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

/// Interface for the [JsonWebKey dictionary][1].
///
/// See also list of [registered parameters][2].
///
/// [1]: https://www.w3.org/TR/WebCryptoAPI/#JsonWebKey-dictionary
/// [2]: https://www.iana.org/assignments/jose/jose.xhtml#web-key-parameters
class JsonWebKey {
  String kty;
  String use;
  List<String> key_ops;
  String alg;
  bool ext;
  String crv;
  String x;
  String y;
  String d;
  String n;
  String e;
  String p;
  String q;
  String dp;
  String dq;
  String qi;
  List<RsaOtherPrimesInfo> oth;
  String k;

  JsonWebKey({
    this.kty,
    this.use,
    this.key_ops,
    this.alg,
    this.ext,
    this.crv,
    this.x,
    this.y,
    this.d,
    this.n,
    this.e,
    this.p,
    this.q,
    this.dp,
    this.dq,
    this.qi,
    this.oth,
    this.k,
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
      if (json.containsKey(k) && json[k] is! String) {
        throw FormatException('JWK entry "$k" must be a string', json);
      }
    }
    List<String> key_ops;
    if (json.containsKey('key_ops')) {
      if (json['key_ops'] is! List ||
          (json['key_ops'] as List).any((e) => e is! String)) {
        throw FormatException(
            'JWK entry "key_ops" must be a list of strings', json);
      }
      key_ops = (json['key_ops'] as List).map((e) => e as String).toList();
    }

    if (json.containsKey('ext') && json['ext'] is! bool) {
      throw FormatException('JWK entry "ext" must be boolean', json);
    }
    List<RsaOtherPrimesInfo> oth;
    if (json.containsKey('oth')) {
      if (json['oth'] is! List || (json['oth'] as List).any((e) => e is! Map)) {
        throw FormatException('JWK entry "oth" must be list of maps', json);
      }
      oth = (json['oth'] as List<Map>).map((json) {
        return RsaOtherPrimesInfo.fromJson(json);
      }).toList();
    }
    return JsonWebKey(
      kty: json['kty'] as String,
      use: json['use'] as String,
      key_ops: key_ops,
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

  Map<String, Object> toJson() {
    final json = <String, Object>{};

    // Set properties from all the string keys
    if (kty != null) {
      json['kty'] = kty;
    }
    if (use != null) {
      json['use'] = use;
    }
    if (alg != null) {
      json['alg'] = alg;
    }
    if (crv != null) {
      json['crv'] = crv;
    }
    if (x != null) {
      json['x'] = x;
    }
    if (y != null) {
      json['y'] = y;
    }
    if (d != null) {
      json['d'] = d;
    }
    if (n != null) {
      json['n'] = n;
    }
    if (e != null) {
      json['e'] = e;
    }
    if (p != null) {
      json['p'] = p;
    }
    if (q != null) {
      json['q'] = q;
    }
    if (dp != null) {
      json['dp'] = dp;
    }
    if (dq != null) {
      json['dq'] = dq;
    }
    if (qi != null) {
      json['qi'] = qi;
    }
    if (k != null) {
      json['k'] = k;
    }

    // Set non-string properties
    if (key_ops != null) {
      json['key_ops'] = key_ops;
    }
    if (ext != null) {
      json['ext'] = ext;
    }
    if (oth != null) {
      json['oth'] = oth.map((e) => e.toJson()).toList();
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
class RsaOtherPrimesInfo {
  String r;
  String d;
  String t;

  RsaOtherPrimesInfo({
    this.r,
    this.d,
    this.t,
  });

  static RsaOtherPrimesInfo fromJson(Map json) {
    for (final k in ['r', 'd', 't']) {
      if (json[k] is! String) {
        throw FormatException('"oth" entries in a JWK must contain "$k"', json);
      }
    }
    return RsaOtherPrimesInfo(
      r: json['r'] as String,
      d: json['d'] as String,
      t: json['t'] as String,
    );
  }

  Map<String, Object> toJson() {
    return <String, Object>{
      'r': r,
      'd': d,
      't': t,
    };
  }
}
