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

import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';
import '../utils/utils.dart';
import '../utils/testrunner.dart';
import '../utils/detected_runtime.dart';

class _KeyPair<S, T> implements KeyPair<S, T> {
  @override
  final S privateKey;

  @override
  final T publicKey;

  _KeyPair({required this.privateKey, required this.publicKey});
}

final runner = TestRunner.asymmetric<EcdhPrivateKey, EcdhPublicKey>(
  algorithm: 'ECDH',
  importPrivateRawKey: null, // not supported
  exportPrivateRawKey: null,
  // HACK: PKCS8 is not support for ECDH / ECDSA on firefox:
  // https://bugzilla.mozilla.org/show_bug.cgi?id=1133698
  //
  // So filter away PKCS8 test data and functions when running on gecko.
  importPrivatePkcs8Key: nullOnFirefox((keyData, keyImportParams) =>
      EcdhPrivateKey.importPkcs8Key(keyData, curveFromJson(keyImportParams))),
  exportPrivatePkcs8Key: nullOnFirefox((key) => key.exportPkcs8Key()),
  importPrivateJsonWebKey: (jsonWebKeyData, keyImportParams) =>
      EcdhPrivateKey.importJsonWebKey(
          jsonWebKeyData, curveFromJson(keyImportParams)),
  exportPrivateJsonWebKey: (key) => key.exportJsonWebKey(),
  importPublicRawKey: (keyData, keyImportParams) =>
      EcdhPublicKey.importRawKey(keyData, curveFromJson(keyImportParams)),
  exportPublicRawKey: (key) => key.exportRawKey(),
  importPublicSpkiKey: (keyData, keyImportParams) =>
      EcdhPublicKey.importSpkiKey(keyData, curveFromJson(keyImportParams)),
  exportPublicSpkiKey: (key) => key.exportSpkiKey(),
  importPublicJsonWebKey: (jsonWebKeyData, keyImportParams) =>
      EcdhPublicKey.importJsonWebKey(
          jsonWebKeyData, curveFromJson(keyImportParams)),
  exportPublicJsonWebKey: (key) => key.exportJsonWebKey(),
  generateKeyPair: (generateKeyPairParams) async {
    // Use public / private keys from two different pairs, as if they had been
    // exchanged.
    final a = await EcdhPrivateKey.generateKey(curveFromJson(
      generateKeyPairParams,
    ));
    final b = await EcdhPrivateKey.generateKey(curveFromJson(
      generateKeyPairParams,
    ));
    return _KeyPair(
      privateKey: a.privateKey,
      publicKey: b.publicKey,
    );
  },
  deriveBits: (keys, length, deriveParams) => keys.privateKey.deriveBits(
    length,
    keys.publicKey,
  ),
  testData: _testData.map((c) => {
        ...c,
        'privatePkcs8KeyData': nullOnFirefox(c['privatePkcs8KeyData']),
      }),
);

void main() {
  test('generate ECDH test case', () async {
    await runner.generate(
      generateKeyParams: {'curve': curveToJson(EllipticCurve.p256)},
      importKeyParams: {'curve': curveToJson(EllipticCurve.p256)},
      deriveParams: {},
      maxDeriveLength: 32,
    );
  });

  runner.runTests();
}

// Allow single quotes for hardcoded testData written as JSON:
// ignore_for_file: prefer_single_quotes
final _testData = [
  {
    "name": "generated on boringssl/linux at 2020-01-22T23:24:34",
    "privatePkcs8KeyData":
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg3aTiZ7odKAODYk4BpZlzulBCB/BptmxjtvrzyXI71UyhRANCAATl0GVa8O1sXXf2NV5qGJ/9/Vq8PVWCZuezADa1F0Vr2TaB8BseZIW+rhmEmLC2FfCdxj9NmLp00SilRTm40Hxm",
    "privateJsonWebKeyData": {
      "kty": "EC",
      "crv": "P-256",
      "x": "5dBlWvDtbF139jVeahif_f1avD1VgmbnswA2tRdFa9k",
      "y": "NoHwGx5khb6uGYSYsLYV8J3GP02YunTRKKVFObjQfGY",
      "d": "3aTiZ7odKAODYk4BpZlzulBCB_BptmxjtvrzyXI71Uw"
    },
    "publicRawKeyData":
        "BHiIXxrwhM92v4ueDrj3x1JJY4uS+II/IJPjqMvaKj/QfoOllnEkrnaOW1owBYRBMnP0pPouPkqbVfPACMUsfKs=",
    "publicSpkiKeyData":
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeIhfGvCEz3a/i54OuPfHUklji5L4gj8gk+Ooy9oqP9B+g6WWcSSudo5bWjAFhEEyc/Sk+i4+SptV88AIxSx8qw==",
    "publicJsonWebKeyData": {
      "kty": "EC",
      "crv": "P-256",
      "x": "eIhfGvCEz3a_i54OuPfHUklji5L4gj8gk-Ooy9oqP9A",
      "y": "foOllnEkrnaOW1owBYRBMnP0pPouPkqbVfPACMUsfKs"
    },
    "derivedBits": "WA==",
    "derivedLength": 7,
    "importKeyParams": {"curve": "p-256"},
    "deriveParams": {}
  },
  {
    "name": "generated on chrome/linux at 2020-01-22T23:24:39",
    "privatePkcs8KeyData":
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg5AWOpgxJFPrYFT35Cd9NzjY/42GMqXHjN2u7nr4vTxmhRANCAAQ6JX8rvqAWaBf62fiBWeRSQ4VmSFtbXiBeMPlW7kvdm+CYn5qysrOmwWQF7ozYqksgU2rq/VxiOIDEA/0jwKih",
    "privateJsonWebKeyData": {
      "kty": "EC",
      "crv": "P-256",
      "x": "OiV_K76gFmgX-tn4gVnkUkOFZkhbW14gXjD5Vu5L3Zs",
      "y": "4JifmrKys6bBZAXujNiqSyBTaur9XGI4gMQD_SPAqKE",
      "d": "5AWOpgxJFPrYFT35Cd9NzjY_42GMqXHjN2u7nr4vTxk"
    },
    "publicRawKeyData":
        "BCjk7bfchTtYegPTteeUP+MrjJKfV7MqOZXFoS1GixVyRhk7MGC0Sc+2mdO1b3P1vR0F9l1pEk1hZfrbPdRs10U=",
    "publicSpkiKeyData":
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKOTtt9yFO1h6A9O155Q/4yuMkp9Xsyo5lcWhLUaLFXJGGTswYLRJz7aZ07Vvc/W9HQX2XWkSTWFl+ts91GzXRQ==",
    "publicJsonWebKeyData": {
      "kty": "EC",
      "crv": "P-256",
      "x": "KOTtt9yFO1h6A9O155Q_4yuMkp9Xsyo5lcWhLUaLFXI",
      "y": "Rhk7MGC0Sc-2mdO1b3P1vR0F9l1pEk1hZfrbPdRs10U"
    },
    "derivedBits": "iZA=",
    "derivedLength": 15,
    "importKeyParams": {"curve": "p-256"},
    "deriveParams": {}
  },
  {
    "name": "generated on firefox/linux at 2020-01-26T19:36:54",
    "privateJsonWebKeyData": {
      "kty": "EC",
      "crv": "P-256",
      "x": "CEFhbltPwubSZ7uvcAStaPsQiAzrd8Lg0ABAwSDLx2M",
      "y": "htguB5lc8x5uKJ_Uj8Mg_kXYLqdxYfFxYW0fWTpSP78",
      "d": "r5YhnToYxcqOHKSr4E_IRMuGvOc0fF0NeEYmc1i6Yxw"
    },
    "publicRawKeyData":
        "BJlCZHJvjqvdpytyJR1Rv4tzlMWWTNw0zEAtDLiIHrZBvKXhSN5y1ZWWhDQFFkKz91MpeA2PMN9YrN9w4aAMTA0=",
    "publicSpkiKeyData":
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmUJkcm+Oq92nK3IlHVG/i3OUxZZM3DTMQC0MuIgetkG8peFI3nLVlZaENAUWQrP3Uyl4DY8w31is33DhoAxMDQ==",
    "publicJsonWebKeyData": {
      "kty": "EC",
      "crv": "P-256",
      "x": "mUJkcm-Oq92nK3IlHVG_i3OUxZZM3DTMQC0MuIgetkE",
      "y": "vKXhSN5y1ZWWhDQFFkKz91MpeA2PMN9YrN9w4aAMTA0"
    },
    "derivedBits": "sA==",
    "derivedLength": 6,
    "importKeyParams": {"curve": "p-256"},
    "deriveParams": {}
  },

  /// Safari and WebKit on Mac (with CommonCrypto) does not support P-521, see:
  /// https://bugs.webkit.org/show_bug.cgi?id=216755
  ...(nullOnSafari(_testDataWithP521) ?? <Map>[]),

  // TODO: generate on firefox, once the import/export pkcs8 has been figured out
];

final _testDataWithP521 = [
  {
    "name": "P521/528 generated on boringssl/linux at 2020-01-23T18:24:14",
    "privatePkcs8KeyData":
        "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBPOq4715seXYBMrMTxtrP7kltsIc3b9CycGc6xNAmx7aUQyiFkkuFWf6Re5C9AgwJwQRxkY14fSm2Q3WwPM6PoxahgYkDgYYABABwixuqn89nBPIk4oUHnw9ZZqGT+bhSu8Zju3jRd2eKpIGCSvhGhzG7sdlHl3c0z/0Y2G95d9OiyiGjpgEN1leqrwEpCSr3ZzbP18q/gQ8IzCIAGXgBLvbA+gaolSGqStyYn4AbAMdXALx9g90UCstqIO2zSvTl/Hh+Pc98JSe5YCzSSg==",
    "privateJsonWebKeyData": {
      "kty": "EC",
      "crv": "P-521",
      "x":
          "AHCLG6qfz2cE8iTihQefD1lmoZP5uFK7xmO7eNF3Z4qkgYJK-EaHMbux2UeXdzTP_RjYb3l306LKIaOmAQ3WV6qv",
      "y":
          "ASkJKvdnNs_Xyr-BDwjMIgAZeAEu9sD6BqiVIapK3JifgBsAx1cAvH2D3RQKy2og7bNK9OX8eH49z3wlJ7lgLNJK",
      "d":
          "ATzquO9ebHl2ATKzE8baz-5JbbCHN2_QsnBnOsTQJse2lEMohZJLhVn-kXuQvQIMCcEEcZGNeH0ptkN1sDzOj6MW"
    },
    "publicRawKeyData":
        "BAFZiFCz9cHz/k9DZOb6wxZKqzpoemGisvlmkuVaB7J2Od1qp4MHyWCnXpws26TEqg/cSgZQMye2+Sih3qUFX/3AQgA7OiqrVeL4cTWsaej833S8EKyE2BOQe+nLPEvAvaJAufeH+IctMXhoL0aKw56uueyeBxxoIZRv4/TX+C/P//g2WA==",
    "publicSpkiKeyData":
        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBWYhQs/XB8/5PQ2Tm+sMWSqs6aHphorL5ZpLlWgeydjndaqeDB8lgp16cLNukxKoP3EoGUDMntvkood6lBV/9wEIAOzoqq1Xi+HE1rGno/N90vBCshNgTkHvpyzxLwL2iQLn3h/iHLTF4aC9GisOerrnsngccaCGUb+P01/gvz//4Nlg=",
    "publicJsonWebKeyData": {
      "kty": "EC",
      "crv": "P-521",
      "x":
          "AVmIULP1wfP-T0Nk5vrDFkqrOmh6YaKy-WaS5VoHsnY53WqngwfJYKdenCzbpMSqD9xKBlAzJ7b5KKHepQVf_cBC",
      "y":
          "ADs6KqtV4vhxNaxp6PzfdLwQrITYE5B76cs8S8C9okC594f4hy0xeGgvRorDnq657J4HHGghlG_j9Nf4L8__-DZY"
    },
    "derivedBits":
        "ANKd9Y53XFXIW2uHp4EcVnDmFKNoJ2fga+zYPkD4tl3lmvAl6ACO/KkS8JQ3YPnR9xvuyHXqkeNewCwvoKdzY946",
    "derivedLength": 528,
    "importKeyParams": {"curve": "p-521"},
    "deriveParams": {}
  },
  {
    "name": "P521/528 generated on chrome/linux at 2020-01-23T18:24:21",
    "privatePkcs8KeyData":
        "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIABsDAGD5XWWvzhnnzCyvNAD2taLLIDFzXwHx78/uPr/kMNRU5KN7ZGkFypJQ0VRHvqUae5xAftQBVINy7U+9AbaKhgYkDgYYABAHjLeYz6+CSi8B9WmAIvHlmLsYEeUUsr0KKFD3lB4zaK1e4qo6n6Y04oBZBs40v6baz7iZt0vloqnlCATRiwce7ZQCzPWKJXDGm/UZKgRUBhl5/JBnlITQt1iwKIT5Q6/47afZTSfxrdoBcPAiId73VJq7fn9iJwRRMGAyYqqHmD6zlWA==",
    "privateJsonWebKeyData": {
      "kty": "EC",
      "crv": "P-521",
      "x":
          "AeMt5jPr4JKLwH1aYAi8eWYuxgR5RSyvQooUPeUHjNorV7iqjqfpjTigFkGzjS_ptrPuJm3S-WiqeUIBNGLBx7tl",
      "y":
          "ALM9YolcMab9RkqBFQGGXn8kGeUhNC3WLAohPlDr_jtp9lNJ_Gt2gFw8CIh3vdUmrt-f2InBFEwYDJiqoeYPrOVY",
      "d":
          "AAbAwBg-V1lr84Z58wsrzQA9rWiyyAxc18B8e_P7j6_5DDUVOSje2RpBcqSUNFUR76lGnucQH7UAVSDcu1PvQG2i"
    },
    "publicRawKeyData":
        "BAHFcqB1M8eMxMcy41W0vhqe/UHuoq6muZn+UR0JRVnJmtSAdESTaRu/wCSjun3K+cTOlKMKvRpBNn75zc4MTuJ/SwFdjjm3upV4aWYGKyUjHUEyb2aEAwXYgY2QtNTVs7+L5rJeFL5M0m16XqLkg4kWTSoVQpBt2WJZy30swHUlPuCPbw==",
    "publicSpkiKeyData":
        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBxXKgdTPHjMTHMuNVtL4anv1B7qKuprmZ/lEdCUVZyZrUgHREk2kbv8Ako7p9yvnEzpSjCr0aQTZ++c3ODE7if0sBXY45t7qVeGlmBislIx1BMm9mhAMF2IGNkLTU1bO/i+ayXhS+TNJtel6i5IOJFk0qFUKQbdliWct9LMB1JT7gj28=",
    "publicJsonWebKeyData": {
      "kty": "EC",
      "crv": "P-521",
      "x":
          "AcVyoHUzx4zExzLjVbS-Gp79Qe6irqa5mf5RHQlFWcma1IB0RJNpG7_AJKO6fcr5xM6Uowq9GkE2fvnNzgxO4n9L",
      "y":
          "AV2OObe6lXhpZgYrJSMdQTJvZoQDBdiBjZC01NWzv4vmsl4UvkzSbXpeouSDiRZNKhVCkG3ZYlnLfSzAdSU-4I9v"
    },
    "derivedBits":
        "ABa2Lr/ImF+AskXCqyO8fWQjh7YNoiynFMbAw6bmDZT/1hVNbAWIyKTjlgRc6YQvV/3alD3SlSCxlEc0BkGGUMiS",
    "derivedLength": 528,
    "importKeyParams": {"curve": "p-521"},
    "deriveParams": {}
  },
  {
    "name": "P521/528 generated firefox/linux at 2020-01-26T19:39:32",
    "privateJsonWebKeyData": {
      "kty": "EC",
      "crv": "P-521",
      "x":
          "AVMsmI3qFRK0YvbHdHVM32Jkv-2A-XpoqzCUzSSwYTImiIotBoE2Lbx9aIR34E8aU96R68K5nb2AIkVm1knxJDfo",
      "y":
          "ABgohNvlwwKqYzj8pFd5qYHmwk8uAvjRRTjOwWo5Y_rPnumGLlZwLm0QrFJ6-OnXKJcmSfSsFVRZx00k-ANH8hNK",
      "d":
          "AU1zr6Fn9zQOp9PYHbOoVt56nDfPgU9hh5BBSPyJdpuNnK-WsyPJ66oBv_Oj7E9krila57wKl54Gj0vfTiR8pU-x"
    },
    "publicRawKeyData":
        "BAHgS8NJglQ69SeU8yGU3QWbNyjyUG4ZvsJJIaYZGqSlbgqZZMLAc5upu9/bEyBL7rgn3wBWRB5IC+F1pM/lhNUpogCzRbB9MqvFCHQxjOtLROI2baiAVnvZ31AWYadWvLeqJdIdFdLgOveK1ORVkDIJT/m5rs1jW1KDc0SYLyGtAGWW1g==",
    "publicSpkiKeyData":
        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB4EvDSYJUOvUnlPMhlN0Fmzco8lBuGb7CSSGmGRqkpW4KmWTCwHObqbvf2xMgS+64J98AVkQeSAvhdaTP5YTVKaIAs0WwfTKrxQh0MYzrS0TiNm2ogFZ72d9QFmGnVry3qiXSHRXS4Dr3itTkVZAyCU/5ua7NY1tSg3NEmC8hrQBlltY=",
    "publicJsonWebKeyData": {
      "kty": "EC",
      "crv": "P-521",
      "x":
          "AeBLw0mCVDr1J5TzIZTdBZs3KPJQbhm-wkkhphkapKVuCplkwsBzm6m739sTIEvuuCffAFZEHkgL4XWkz-WE1Smi",
      "y":
          "ALNFsH0yq8UIdDGM60tE4jZtqIBWe9nfUBZhp1a8t6ol0h0V0uA694rU5FWQMglP-bmuzWNbUoNzRJgvIa0AZZbW"
    },
    "derivedBits":
        "AT8SeVde9pfjq+ktYDRrVeYHQJM9c+gflBxlJqIKyJrMIWH5ZTm470ateBrlZr2uNI/lT7OfayxSz6WGkhEZUDXl",
    "derivedLength": 528,
    "importKeyParams": {"curve": "p-521"},
    "deriveParams": {}
  },
];
