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

import 'package:webcrypto/webcrypto.dart';
import 'package:test/test.dart';
import '../utils.dart';
import '../testrunner.dart';

final runner = TestRunner.asymmetric<RsaOaepPrivateKey, RsaOaepPublicKey>(
  algorithm: 'RSA-OAEP',
  importPrivateRawKey: null, // not supported
  exportPrivateRawKey: null,
  importPrivatePkcs8Key: (keyData, keyImportParams) =>
      RsaOaepPrivateKey.importPkcs8Key(keyData, hashFromJson(keyImportParams)),
  exportPrivatePkcs8Key: (key) => key.exportPkcs8Key(),
  importPrivateJsonWebKey: (jsonWebKeyData, keyImportParams) =>
      RsaOaepPrivateKey.importJsonWebKey(
          jsonWebKeyData, hashFromJson(keyImportParams)),
  exportPrivateJsonWebKey: (key) => key.exportJsonWebKey(),
  importPublicRawKey: null, // not supported
  exportPublicRawKey: null,
  importPublicSpkiKey: (keyData, keyImportParams) =>
      RsaOaepPublicKey.importSpkiKey(keyData, hashFromJson(keyImportParams)),
  exportPublicSpkiKey: (key) => key.exportSpkiKey(),
  importPublicJsonWebKey: (jsonWebKeyData, keyImportParams) =>
      RsaOaepPublicKey.importJsonWebKey(
          jsonWebKeyData, hashFromJson(keyImportParams)),
  exportPublicJsonWebKey: (key) => key.exportJsonWebKey(),
  generateKeyPair: (generateKeyPairParams) => RsaOaepPrivateKey.generateKey(
    generateKeyPairParams['modulusLength'],
    BigInt.parse(generateKeyPairParams['publicExponent']),
    hashFromJson(generateKeyPairParams),
  ),
  encryptBytes: (key, data, encryptParams) => key.encryptBytes(
    data,
    label: bytesFromJson(encryptParams, 'label'),
  ),
  decryptBytes: (key, data, decryptParams) => key.decryptBytes(
    data,
    label: bytesFromJson(decryptParams, 'label'),
  ),
  testData: _testData,
);

void main() {
  test('generate RSA-OAEP test case', () async {
    await runner.generate(
      generateKeyParams: {
        'hash': hashToJson(Hash.sha384),
        'modulusLength': 2048,
        'publicExponent': '65537',
      },
      importKeyParams: {'hash': hashToJson(Hash.sha384)},
      encryptDecryptParams: {
        'label': bytesToJson(List.generate(32, (i) => i + 1)),
      },
      maxPlaintext: 64,
      minPlaintext: 8,
      // TODO: Support test cases with invalid encryptDecryptParams for giving wrong label
    );
  });

  runner.runTests();
}

// Allow single quotes for hardcoded testData written as JSON:
// ignore_for_file: prefer_single_quotes
final _testData = [
  {
    "name":
        "RSA-OAEP-256/no-label generated on boringssl/linux at 2020-01-21T23:21:35",
    "privatePkcs8KeyData":
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCjhY6y1NLJXBYVLSdjhRpYgtB9Yeh3E2mYc0DW+zjSohp+jA/3ox4drN7EugzrV5X2SlyvGZWJLPJjyqNBgcdDvDxkkAFuJM8RXqcUCbv2a7UIy6HApivcAExxS63BNhnE7N5miMF23bewGxakl/W9y/v9TFN8PzEtCco+vS6XxbX8P1dswww5lUy1jHmmJoFevrd18t/X5jotx11bHjgms87wTNFRSzhQwml8aXwVw+jdkNkiEXvsjSMoCM8qWTtMj6jbCy3EoUkR2NgN/azp4LQjs41r30XFz/VROqwe9uMtE3hGggUF1fFuSUp6Cw6dzKQNaPZYbB23uL/TwWrzAgMBAAECggEAAfxxS0LCfKedrQwrWk4Xj9Om7J7vz+JweeWMeA/9FLHbWIYi+4MDrqCW5BTOa11Y+PDWR1osMspU91lSukz1OqFiqmYFXm0cBr37kYa8vbV5MW4nvMtH5Rgr1YRxy9L4ZSfrW5t1nhf7TyxFDiK6XV/I4761lOC/nChuSGzL0BQVs9uZ/4KPy9VEHrhYikEGBRedd1a9coP5nUY0V9T7C+7vYLnc8fwfhcbEnNivMnoeBNsls04iv/Scq+elGjVjC62aFbFf+426XmqtTHPJjJCQUaG9clMaqeGSEa6ON8w5xeY2NdcIAuYbqmKNdKXo1dopsOYcMNVBbWofKt9p4QKBgQDW+OFOs4F8FPSE758mNxo6SB5Rn0KjGRBGUgMIX1Eb1hHgIrtnJDNImUtju46ywJ/ApjW+FV5JJ7j/JvorBzCUuTXgOHVp2RlOirU1gtL94c9e2mcm78PRIScLwVyMq/hdhD+gj7Cau/nMEwRMejE93mL2le6ybVDe5gOuuuQRPQKBgQDCuuhfM0mBON6LULY/TRkNzg9+ngTjk+0RC2xVnXdHwnzZCurtcO5JJ+8twblTQCK2DdCin2fsoQOJd06jio8pcvtOpp47QnVZrWVVo0J7dgV4ma53MAfXYbClnxqeDJSHjIfoa84/NysUeW41krVRd7HdXdAbF6qZTBA3XsnP7wKBgGFbzCapk34Pu4ItR+W11PIKUXjj6PkW09EVOXxkNsall+jrsfYPZg5+Jq+fdQwtwuwsGnDhGpeFHvqnu2sbUXw5uVW4HCz4/sYced8nRclnqFQsE8WFlyiynA1t4C1xgQVRbMOZ8ADUG1i6UBsWyBBeFHHbC4TRj2uzvn029S19AoGAQO6MH3p9jx5EbtX5/z+ZFBZa6lCMtsoTqbRSanX4WTBL6x+N2KDog/JR+cL4Jf9j06rln+RhhfDmugbTbQr908dobwB2ELKHaOC9woGO4JYpGt674zhb1QDZI1DbUkpFmLFOfDy+aCvgLJKVIj4KQeEUqQjoJLCOjVFksuHjj3cCgYEAmUfJfMycIbbce7Klop3RLeaLdSViz/ngtWKmJQWnHH0ZnYNimvcqnfnb9/BwSh05YW0zWzsx/wMy+K/wGE9w+5quAZtoOfn+AlXhxPmC/6Ba3SR/bBNKGJJgA8e8K+ofn1bTFtmMUpFwK90D184bVNnqg4j9LjSs82APHqNuTCI=",
    "privateJsonWebKeyData": {
      "kty": "RSA",
      "use": "enc",
      "alg": "RSA-OAEP-256",
      "d":
          "AfxxS0LCfKedrQwrWk4Xj9Om7J7vz-JweeWMeA_9FLHbWIYi-4MDrqCW5BTOa11Y-PDWR1osMspU91lSukz1OqFiqmYFXm0cBr37kYa8vbV5MW4nvMtH5Rgr1YRxy9L4ZSfrW5t1nhf7TyxFDiK6XV_I4761lOC_nChuSGzL0BQVs9uZ_4KPy9VEHrhYikEGBRedd1a9coP5nUY0V9T7C-7vYLnc8fwfhcbEnNivMnoeBNsls04iv_Scq-elGjVjC62aFbFf-426XmqtTHPJjJCQUaG9clMaqeGSEa6ON8w5xeY2NdcIAuYbqmKNdKXo1dopsOYcMNVBbWofKt9p4Q",
      "n":
          "o4WOstTSyVwWFS0nY4UaWILQfWHodxNpmHNA1vs40qIafowP96MeHazexLoM61eV9kpcrxmViSzyY8qjQYHHQ7w8ZJABbiTPEV6nFAm79mu1CMuhwKYr3ABMcUutwTYZxOzeZojBdt23sBsWpJf1vcv7_UxTfD8xLQnKPr0ul8W1_D9XbMMMOZVMtYx5piaBXr63dfLf1-Y6LcddWx44JrPO8EzRUUs4UMJpfGl8FcPo3ZDZIhF77I0jKAjPKlk7TI-o2wstxKFJEdjYDf2s6eC0I7ONa99Fxc_1UTqsHvbjLRN4RoIFBdXxbklKegsOncykDWj2WGwdt7i_08Fq8w",
      "e": "AQAB",
      "p":
          "1vjhTrOBfBT0hO-fJjcaOkgeUZ9CoxkQRlIDCF9RG9YR4CK7ZyQzSJlLY7uOssCfwKY1vhVeSSe4_yb6KwcwlLk14Dh1adkZToq1NYLS_eHPXtpnJu_D0SEnC8FcjKv4XYQ_oI-wmrv5zBMETHoxPd5i9pXusm1Q3uYDrrrkET0",
      "q":
          "wrroXzNJgTjei1C2P00ZDc4Pfp4E45PtEQtsVZ13R8J82Qrq7XDuSSfvLcG5U0Aitg3Qop9n7KEDiXdOo4qPKXL7TqaeO0J1Wa1lVaNCe3YFeJmudzAH12GwpZ8angyUh4yH6GvOPzcrFHluNZK1UXex3V3QGxeqmUwQN17Jz-8",
      "dp":
          "YVvMJqmTfg-7gi1H5bXU8gpReOPo-RbT0RU5fGQ2xqWX6Oux9g9mDn4mr591DC3C7CwacOEal4Ue-qe7axtRfDm5VbgcLPj-xhx53ydFyWeoVCwTxYWXKLKcDW3gLXGBBVFsw5nwANQbWLpQGxbIEF4UcdsLhNGPa7O-fTb1LX0",
      "dq":
          "QO6MH3p9jx5EbtX5_z-ZFBZa6lCMtsoTqbRSanX4WTBL6x-N2KDog_JR-cL4Jf9j06rln-RhhfDmugbTbQr908dobwB2ELKHaOC9woGO4JYpGt674zhb1QDZI1DbUkpFmLFOfDy-aCvgLJKVIj4KQeEUqQjoJLCOjVFksuHjj3c",
      "qi":
          "mUfJfMycIbbce7Klop3RLeaLdSViz_ngtWKmJQWnHH0ZnYNimvcqnfnb9_BwSh05YW0zWzsx_wMy-K_wGE9w-5quAZtoOfn-AlXhxPmC_6Ba3SR_bBNKGJJgA8e8K-ofn1bTFtmMUpFwK90D184bVNnqg4j9LjSs82APHqNuTCI"
    },
    "publicSpkiKeyData":
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo4WOstTSyVwWFS0nY4UaWILQfWHodxNpmHNA1vs40qIafowP96MeHazexLoM61eV9kpcrxmViSzyY8qjQYHHQ7w8ZJABbiTPEV6nFAm79mu1CMuhwKYr3ABMcUutwTYZxOzeZojBdt23sBsWpJf1vcv7/UxTfD8xLQnKPr0ul8W1/D9XbMMMOZVMtYx5piaBXr63dfLf1+Y6LcddWx44JrPO8EzRUUs4UMJpfGl8FcPo3ZDZIhF77I0jKAjPKlk7TI+o2wstxKFJEdjYDf2s6eC0I7ONa99Fxc/1UTqsHvbjLRN4RoIFBdXxbklKegsOncykDWj2WGwdt7i/08Fq8wIDAQAB",
    "publicJsonWebKeyData": {
      "kty": "RSA",
      "use": "enc",
      "alg": "RSA-OAEP-256",
      "n":
          "o4WOstTSyVwWFS0nY4UaWILQfWHodxNpmHNA1vs40qIafowP96MeHazexLoM61eV9kpcrxmViSzyY8qjQYHHQ7w8ZJABbiTPEV6nFAm79mu1CMuhwKYr3ABMcUutwTYZxOzeZojBdt23sBsWpJf1vcv7_UxTfD8xLQnKPr0ul8W1_D9XbMMMOZVMtYx5piaBXr63dfLf1-Y6LcddWx44JrPO8EzRUUs4UMJpfGl8FcPo3ZDZIhF77I0jKAjPKlk7TI-o2wstxKFJEdjYDf2s6eC0I7ONa99Fxc_1UTqsHvbjLRN4RoIFBdXxbklKegsOncykDWj2WGwdt7i_08Fq8w",
      "e": "AQAB"
    },
    "plaintext":
        "bGVtZW50dW0gc2NlbGVyaXNxdWUgcXVpcwpldCBuZXF1ZS4gVmVzdGlidWx1bSA=",
    "ciphertext":
        "Bw4Cu8CC6lLpz9jmkl2bZCiBaLbkZp9ObejFvHVSKTPxAQY/HH5MmgHgLDiEdnZbM2nxxxu+3t82tm0rau57WS86Pwr0L5gmWOFyK4Lf0uM82qql9yOFYBqT/y7j26a3e6b/1WWwnvGbQW8zvnkSZJXGokh5pCIIhklEwu8/aih28KSxL4yTy+nXeBNMvKTRIDxna4y1fqC/uKTsDyI3DedPw6zjLwWp01LEI4psdLiOjNGyWY6q2oVIKet65h+gX7O2eXvVO2F/sVOvvnRUxk9DET/d7E92S4mUda3d/if8rEged/uizlU7dbxPF8mMvirtayg0SF1k6PsO1TclFA==",
    "importKeyParams": {"hash": "sha-256"},
    "encryptDecryptParams": {"label": null}
  },
  {
    "name":
        "RSA-OAEP-256/no-label generated on chrome/linux at 2020-01-21T23:21:45",
    "privatePkcs8KeyData":
        "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDAhljCmnd7BFuxKqFfRXi3QpkvEqQJXYeu5b6VUO3daHFIndDV5BErIjwI74bVP25KZ4DnuAxtbjH2CHazm6GMIAUyBTA5su5nQhXVK2NmgNj7gFCOOvjUXCe0SLr+ZAewAcONM0weIwDnJwipgxfWn/TdXjbttTc8rYYrL15gnPyQ3F1EsZEBXfs1CtplMwvtTXByk5Y3gHFKQI5qUdhPZ5hgahbU8sbH1MD1qly2+NtSp4wBYwzjvN2A5nV5y0ejFpEewOo2qau9pwXzhdtB1xzuAohQwLyVx8Cip15WM8DYo2W6vZo6IdAsLT2pC5/ImkUNPBTXqR8ygSR0QlNnAgMBAAECggEAELQXQ1sPfrbUFbzzH0bxwESg8bqWTNG2kfAQ5veMi6ciHQDEO6p76tgfiU7uzdWhBgeQ4YnQWjYzU3tMgSzBiVzF1p8onfjuQjszlbkb+Kq5KKjrVEu9hv8v2q5suuGG4Thl9Pw8YGj9DREP6VUcXlymbAZekaUlU7hiaaDEeXE+vzS8Ama9l7ksfjhy61EEUsLC7HPYYrYe7K1BGllVkSWBhLU37lnXOi+cGOzwNMHocLQfLLpfkC+yqXsaskicbknJzbZge0e2RdsY2zJxzsOxV0yMGpocJJcsKTz8RY8NXYB9IbfXKoGH2b6rrQyJmLdx1G7w9utV84FlscW0cQKBgQDvLUyS9g0S/AKfP6UBER2I0wF7NO+rSFJqytRiiZdToZnzBs4jpdRdJKNnSDO4sKOCRRMNn5DkYoppltvxLq5xBbCTDG/E1ZGbJj6Q0svj104FFwF9z/0TMW46FSTO/2W7tUZkuAv7pOfh45B/7SVJT/v+OhWgEGOGvNkjQGw/5QKBgQDOEQNasH0NcWCSdqk964s31aIOTxMWIZUk5bTZJMiRtsJzRmVxiaAB51HYE+OLi8apWKcjfNrhKcvDMQH0Vn1VzxgCPHNDvXjiU8/jVJ/O11VP5Mk9U7tYDJYAouOmufm9newO3kWGWFLyjGSrMnr5ZcB4LOQenGWFyEHtyj1ZWwKBgGPph3BoyqNglPPTUWl1reHHS3odbfUePBeSbVBQa9+qxTXJZPltP549POlbNwfy+grkMgZh3tQY+fsL4wsIViSunMmAy3vtP2sReddjx3qBKX1k0+GrreuDnakzxfGWrPfRzPssCw1vINKzDlzyQr4yZHEZ8Iix7/GMGCTqt42lAoGAMlcBpMP8qK4L03vdeFz0U52Cy1AR75QgpTTgazOLM92bvyFxYr0mM5DY85pYOhzZWUFpA0hbCCp3tqVgPtpqH+5JhTJTTjcZMuEapgRkTdlY4/2WE79Cww3AD0O7rV09X08W/cLa5Sjqioo1hYT9ebObwz/kMn4uZvI2+Oow9oUCgYBplZlyOCScKGXygvrJrjBSfyCzheSaKwnBdiaZjCxRwG9fW3xhlPrNTS6rDcWseW3tpWA5jaaqj7SrpOCAZKXZUL2UmeftEaPIRbYh3X0kzWVYT6mQFwFQb3mi+GvUejeDI9WySEt8u5TmEnpB6M+nbUlTl7DWLLIVQzU5e6qY6Q==",
    "privateJsonWebKeyData": {
      "kty": "RSA",
      "alg": "RSA-OAEP-256",
      "d":
          "ELQXQ1sPfrbUFbzzH0bxwESg8bqWTNG2kfAQ5veMi6ciHQDEO6p76tgfiU7uzdWhBgeQ4YnQWjYzU3tMgSzBiVzF1p8onfjuQjszlbkb-Kq5KKjrVEu9hv8v2q5suuGG4Thl9Pw8YGj9DREP6VUcXlymbAZekaUlU7hiaaDEeXE-vzS8Ama9l7ksfjhy61EEUsLC7HPYYrYe7K1BGllVkSWBhLU37lnXOi-cGOzwNMHocLQfLLpfkC-yqXsaskicbknJzbZge0e2RdsY2zJxzsOxV0yMGpocJJcsKTz8RY8NXYB9IbfXKoGH2b6rrQyJmLdx1G7w9utV84FlscW0cQ",
      "n":
          "wIZYwpp3ewRbsSqhX0V4t0KZLxKkCV2HruW-lVDt3WhxSJ3Q1eQRKyI8CO-G1T9uSmeA57gMbW4x9gh2s5uhjCAFMgUwObLuZ0IV1StjZoDY-4BQjjr41FwntEi6_mQHsAHDjTNMHiMA5ycIqYMX1p_03V427bU3PK2GKy9eYJz8kNxdRLGRAV37NQraZTML7U1wcpOWN4BxSkCOalHYT2eYYGoW1PLGx9TA9apctvjbUqeMAWMM47zdgOZ1ectHoxaRHsDqNqmrvacF84XbQdcc7gKIUMC8lcfAoqdeVjPA2KNlur2aOiHQLC09qQufyJpFDTwU16kfMoEkdEJTZw",
      "e": "AQAB",
      "p":
          "7y1MkvYNEvwCnz-lAREdiNMBezTvq0hSasrUYomXU6GZ8wbOI6XUXSSjZ0gzuLCjgkUTDZ-Q5GKKaZbb8S6ucQWwkwxvxNWRmyY-kNLL49dOBRcBfc_9EzFuOhUkzv9lu7VGZLgL-6Tn4eOQf-0lSU_7_joVoBBjhrzZI0BsP-U",
      "q":
          "zhEDWrB9DXFgknapPeuLN9WiDk8TFiGVJOW02STIkbbCc0ZlcYmgAedR2BPji4vGqVinI3za4SnLwzEB9FZ9Vc8YAjxzQ7144lPP41SfztdVT-TJPVO7WAyWAKLjprn5vZ3sDt5FhlhS8oxkqzJ6-WXAeCzkHpxlhchB7co9WVs",
      "dp":
          "Y-mHcGjKo2CU89NRaXWt4cdLeh1t9R48F5JtUFBr36rFNclk-W0_nj086Vs3B_L6CuQyBmHe1Bj5-wvjCwhWJK6cyYDLe-0_axF512PHeoEpfWTT4aut64OdqTPF8Zas99HM-ywLDW8g0rMOXPJCvjJkcRnwiLHv8YwYJOq3jaU",
      "dq":
          "MlcBpMP8qK4L03vdeFz0U52Cy1AR75QgpTTgazOLM92bvyFxYr0mM5DY85pYOhzZWUFpA0hbCCp3tqVgPtpqH-5JhTJTTjcZMuEapgRkTdlY4_2WE79Cww3AD0O7rV09X08W_cLa5Sjqioo1hYT9ebObwz_kMn4uZvI2-Oow9oU",
      "qi":
          "aZWZcjgknChl8oL6ya4wUn8gs4XkmisJwXYmmYwsUcBvX1t8YZT6zU0uqw3FrHlt7aVgOY2mqo-0q6TggGSl2VC9lJnn7RGjyEW2Id19JM1lWE-pkBcBUG95ovhr1Ho3gyPVskhLfLuU5hJ6QejPp21JU5ew1iyyFUM1OXuqmOk"
    },
    "publicSpkiKeyData":
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwIZYwpp3ewRbsSqhX0V4t0KZLxKkCV2HruW+lVDt3WhxSJ3Q1eQRKyI8CO+G1T9uSmeA57gMbW4x9gh2s5uhjCAFMgUwObLuZ0IV1StjZoDY+4BQjjr41FwntEi6/mQHsAHDjTNMHiMA5ycIqYMX1p/03V427bU3PK2GKy9eYJz8kNxdRLGRAV37NQraZTML7U1wcpOWN4BxSkCOalHYT2eYYGoW1PLGx9TA9apctvjbUqeMAWMM47zdgOZ1ectHoxaRHsDqNqmrvacF84XbQdcc7gKIUMC8lcfAoqdeVjPA2KNlur2aOiHQLC09qQufyJpFDTwU16kfMoEkdEJTZwIDAQAB",
    "publicJsonWebKeyData": {
      "kty": "RSA",
      "alg": "RSA-OAEP-256",
      "n":
          "wIZYwpp3ewRbsSqhX0V4t0KZLxKkCV2HruW-lVDt3WhxSJ3Q1eQRKyI8CO-G1T9uSmeA57gMbW4x9gh2s5uhjCAFMgUwObLuZ0IV1StjZoDY-4BQjjr41FwntEi6_mQHsAHDjTNMHiMA5ycIqYMX1p_03V427bU3PK2GKy9eYJz8kNxdRLGRAV37NQraZTML7U1wcpOWN4BxSkCOalHYT2eYYGoW1PLGx9TA9apctvjbUqeMAWMM47zdgOZ1ectHoxaRHsDqNqmrvacF84XbQdcc7gKIUMC8lcfAoqdeVjPA2KNlur2aOiHQLC09qQufyJpFDTwU16kfMoEkdEJTZw",
      "e": "AQAB"
    },
    "plaintext": "cmJpCmV1IGVsaXQgc2VkIGxpZw==",
    "ciphertext":
        "MxFmco2YRJsuxM4IpMqc1AEfpTvl0ZKQeL1QufUUWIo5vG2P7Z5CN/uIA6XMxR777G2Xa/jq2ZiSAcjYuGFXnc1+FiJxbXwaOjjZkqBys/XI/G7yVrumPftoVRN/WZF7k2q/6zYEq+ykffkRPMyQFksN0zCiCAq+CevFA/iR6MYRbFx+fqhlFOQa6dIpZez4wJgruMtYyJWGvSOqeLucCkVICwFv8nZp1EIDCJT9R+qQwjggBrM5bd7XX14Vn5xdPPogHPhkJfVTVb9suCBLaXKXM++Yhq/D5Z7un2GXodhxUJAmgMF9JRz7CkHUlM1tikPiqZMcJp9/p2tz9ofHHQ==",
    "importKeyParams": {"hash": "sha-256"},
    "encryptDecryptParams": {"label": null}
  },
  {
    "name":
        "RSA-OAEP-256/no-label generated on firefox/linux at 2020-01-21T23:21:52",
    "privatePkcs8KeyData":
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDYEPx9+JvHfsOLRPlBvYzL7qZ8rlTaRSAoIBHlGJXO+wroHXEV8+YGKtVa+aeLOmDH3EpIYldnTHjtsD/w7a/+U7yATBhrt2fma/V4TCQONHeGFBT1EJ1jcTJXxNVHlqwEyGo2kb2m5oK875wHaicJTxqurBRC6Pj523Wtigfpi6xmpojqvck8AZjjYvca4yX3RWMNVRO3VzQa1i7SRuGSakcnoFKsfdgTLXjivPBiAEZRpYuHqicvGLP11xt1U/wzKNIZdAmnBio/r+x+pDJqfuJMMcprXf2Vej7C0T4dLoQhKssSfl8s6UGlYCLFcOBoxGGK7C9bFvHLgDO0UyqlAgMBAAECggEAMG66UniAXtsc9SJ8Zw6YuXvg6PDhB15YY3Yw3LRCnHdsjfRPjZay+K3wTmjI9C4dVJ+eLRSSOA8NymXoJ1b4TN+zUOT90mN10FJh31nd+SssoartubNEPG661K7ECjyNibLtEBdiNj/UjYp+ZLEYV/9Z4U6kag00Bjn56nEW7fQd50um7l+ffN0C+rUahP/THSSJtNnx8hYpW++Z2W8I+U0DgVo0VWAYKhy0kpb7J45/yes+8eVNvhoqoRDNBn9WJRhOa80WiSNqjpZ8rS7yYMw/71+TBj9L5WnjrD9e1WU+7AbAU5YbTEwjxeXsz8A9V5ZE5yJ5dcp5HjKha5cwrwKBgQD+mjKa7fFRDqECrktnb8RjTQJ9afjK4r9SeGFIuV7SwcgKKxxutRpVrdUHkDYkPsdiVCPkHt7cVwvbEsflDyygpNJVyUkC/HSS45o8rijn7hkxBYV2Zo+TKC5XydyllxVXlVp/H0aTUkckzPwwCyiss17EzSQpjkBTXQ0/EfJ5BwKBgQDZQKHuUXIXOgdbxf+WZKa1izANnaaX7XMuxSTsxVvCy8Euj09hzL1A9PCa8s/jMRu2i0kgKXRDbAkJGe1X0T2FdWSeNI5Zg+1I3zUlLVOO3vL0QqXE3YxTAtokbrHr8EQosux+sHoG1bPlGR3fps6ttm6NVpXZ1ENZ9ffu3v4v8wKBgCOa0srhzaaFQjUKxNbBRZiRc3Cwei99SD4zQX+XFNCqctwhLUe6IeWreqglHb0x3lY86AwF2Sq9LZZEaRn6ZkZM5nFCxegZ//9uvuoPfP76SCGX4RMuwpNUwi5at3WczEpEQ7SVXhxKHFLkK7xYQybrqqwg+BarowlFcQ3J57vPAoGBALefST6E2EmJYm7PCxeyOrV2z0ay2PvQVmpRdsQoi0Y5sS4JMq8WvV8Jp9NPJyZ/e0zurP/iCcJyrbBjmZd/4t/KOSD+itJeD1BoWCL0DIvVJMQPEM0z9Ea1QmtIpFkm2nULxZfO0VS1izc342gFNOreJtKPPFjAb6y5mLTtBSrBAoGAfVL+GLXUsT8fjJo/l6joHGJlw4D8oQl/gK2i2OD9Fju349PfpowJ7pjq+KSG6fEe1ORI/L49GlYBh70Rho9GV3wlDZNGgB2LPtzDlYNdGI2F4fnCRcLXbynOJG8o8F0Ki5fEMVRLsnpiaojpKGy66PVslvx80mrJV6efkszze9M=",
    "privateJsonWebKeyData": {
      "kty": "RSA",
      "alg": "RSA-OAEP-256",
      "d":
          "MG66UniAXtsc9SJ8Zw6YuXvg6PDhB15YY3Yw3LRCnHdsjfRPjZay-K3wTmjI9C4dVJ-eLRSSOA8NymXoJ1b4TN-zUOT90mN10FJh31nd-SssoartubNEPG661K7ECjyNibLtEBdiNj_UjYp-ZLEYV_9Z4U6kag00Bjn56nEW7fQd50um7l-ffN0C-rUahP_THSSJtNnx8hYpW--Z2W8I-U0DgVo0VWAYKhy0kpb7J45_yes-8eVNvhoqoRDNBn9WJRhOa80WiSNqjpZ8rS7yYMw_71-TBj9L5WnjrD9e1WU-7AbAU5YbTEwjxeXsz8A9V5ZE5yJ5dcp5HjKha5cwrw",
      "n":
          "2BD8ffibx37Di0T5Qb2My-6mfK5U2kUgKCAR5RiVzvsK6B1xFfPmBirVWvmnizpgx9xKSGJXZ0x47bA_8O2v_lO8gEwYa7dn5mv1eEwkDjR3hhQU9RCdY3EyV8TVR5asBMhqNpG9puaCvO-cB2onCU8arqwUQuj4-dt1rYoH6YusZqaI6r3JPAGY42L3GuMl90VjDVUTt1c0GtYu0kbhkmpHJ6BSrH3YEy144rzwYgBGUaWLh6onLxiz9dcbdVP8MyjSGXQJpwYqP6_sfqQyan7iTDHKa139lXo-wtE-HS6EISrLEn5fLOlBpWAixXDgaMRhiuwvWxbxy4AztFMqpQ",
      "e": "AQAB",
      "p":
          "_poymu3xUQ6hAq5LZ2_EY00CfWn4yuK_UnhhSLle0sHICiscbrUaVa3VB5A2JD7HYlQj5B7e3FcL2xLH5Q8soKTSVclJAvx0kuOaPK4o5-4ZMQWFdmaPkyguV8ncpZcVV5Vafx9Gk1JHJMz8MAsorLNexM0kKY5AU10NPxHyeQc",
      "q":
          "2UCh7lFyFzoHW8X_lmSmtYswDZ2ml-1zLsUk7MVbwsvBLo9PYcy9QPTwmvLP4zEbtotJICl0Q2wJCRntV9E9hXVknjSOWYPtSN81JS1Tjt7y9EKlxN2MUwLaJG6x6_BEKLLsfrB6BtWz5Rkd36bOrbZujVaV2dRDWfX37t7-L_M",
      "dp":
          "I5rSyuHNpoVCNQrE1sFFmJFzcLB6L31IPjNBf5cU0Kpy3CEtR7oh5at6qCUdvTHeVjzoDAXZKr0tlkRpGfpmRkzmcULF6Bn__26-6g98_vpIIZfhEy7Ck1TCLlq3dZzMSkRDtJVeHEocUuQrvFhDJuuqrCD4FqujCUVxDcnnu88",
      "dq":
          "t59JPoTYSYlibs8LF7I6tXbPRrLY-9BWalF2xCiLRjmxLgkyrxa9Xwmn008nJn97TO6s_-IJwnKtsGOZl3_i38o5IP6K0l4PUGhYIvQMi9UkxA8QzTP0RrVCa0ikWSbadQvFl87RVLWLNzfjaAU06t4m0o88WMBvrLmYtO0FKsE",
      "qi":
          "fVL-GLXUsT8fjJo_l6joHGJlw4D8oQl_gK2i2OD9Fju349PfpowJ7pjq-KSG6fEe1ORI_L49GlYBh70Rho9GV3wlDZNGgB2LPtzDlYNdGI2F4fnCRcLXbynOJG8o8F0Ki5fEMVRLsnpiaojpKGy66PVslvx80mrJV6efkszze9M"
    },
    "publicSpkiKeyData":
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2BD8ffibx37Di0T5Qb2My+6mfK5U2kUgKCAR5RiVzvsK6B1xFfPmBirVWvmnizpgx9xKSGJXZ0x47bA/8O2v/lO8gEwYa7dn5mv1eEwkDjR3hhQU9RCdY3EyV8TVR5asBMhqNpG9puaCvO+cB2onCU8arqwUQuj4+dt1rYoH6YusZqaI6r3JPAGY42L3GuMl90VjDVUTt1c0GtYu0kbhkmpHJ6BSrH3YEy144rzwYgBGUaWLh6onLxiz9dcbdVP8MyjSGXQJpwYqP6/sfqQyan7iTDHKa139lXo+wtE+HS6EISrLEn5fLOlBpWAixXDgaMRhiuwvWxbxy4AztFMqpQIDAQAB",
    "publicJsonWebKeyData": {
      "kty": "RSA",
      "alg": "RSA-OAEP-256",
      "n":
          "2BD8ffibx37Di0T5Qb2My-6mfK5U2kUgKCAR5RiVzvsK6B1xFfPmBirVWvmnizpgx9xKSGJXZ0x47bA_8O2v_lO8gEwYa7dn5mv1eEwkDjR3hhQU9RCdY3EyV8TVR5asBMhqNpG9puaCvO-cB2onCU8arqwUQuj4-dt1rYoH6YusZqaI6r3JPAGY42L3GuMl90VjDVUTt1c0GtYu0kbhkmpHJ6BSrH3YEy144rzwYgBGUaWLh6onLxiz9dcbdVP8MyjSGXQJpwYqP6_sfqQyan7iTDHKa139lXo-wtE-HS6EISrLEn5fLOlBpWAixXDgaMRhiuwvWxbxy4AztFMqpQ",
      "e": "AQAB"
    },
    "plaintext":
        "Y3ViaWxpYSBDdXJhZTsgQWxpcXVhbSBxdWlzIGhlbmRyZXJpdCBsYWN1cy4KCkRvbmVjIHV0IG5p",
    "ciphertext":
        "fEdX5qyvdwgJITOKryKh6+3OcFYeTTVyA+jVmHv/jUHgl45XJ5l4CXE38FKBDGkoDXFakUARC/JB0+Vzp87icsh+dktxGcFyP1LrH7p8tvOJue2Dk6Mv0XGZOh20mec/5pFtfsKmMtarRD6lUDSxfrpi/W6kiN3c2bfAocMEftoeEh4r7o8hfxd1WK606I6ZhcTbniBaDSJW9wV6fXdLeKdKjrtLl7YkhLGi2nHpXV+vKmUEOXjaM8o/H8Y7n1uq3obccs+2459di+AFXAuL0IuPu9VSr21Rovh4sJ4yRkeBZz1RRZuqRkJu7ydJomQUbTaPNeeJPXd5Q86oz7K2eA==",
    "importKeyParams": {"hash": "sha-256"},
    "encryptDecryptParams": {"label": null}
  },
  {
    "name":
        "RSA-OAEP-384/label generated on boringssl/linux at 2020-01-21T23:24:34",
    "privatePkcs8KeyData":
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDHVYwmUweNTQhzyBXpfKWTmjjQYU6RwQ3wbDfe5MxVFamFsAKpmxy9ilPYJA3QuyeZyf6CgL0jtZRPfRnOQpaJINxhN+GKV7LY/h18iGkNWEHb4Si2qIbcFLG2aVA8zhuwTO2WvHun0xY3jJxnQKR9zbfl9SQcGtMgSieMjPACvOkt6NGhSOlx1lXD/X4T8Mr1mjRtuJSwIVtzyEo+gDFrXxXs21FrMfIiJB4a0uojedpdrjeoZO6p+FXFJbIkP+NXl4Ea/UrHhp5QQUcMBgALky45Ne25LKIMRRXWCr7z0dgIPUOYU9XRVHQnufABdIHOmaES9igl+CvgX6DBO9ApAgMBAAECggEABRC5E+C8goRUfIe3OdSRaxGqU65DVjwZB/TiCxOWlytqoENvn+J5jZ36ITYSVU1qNVPfGC8gD0weEZKI4TdLNr8bZouKW0789BtqAagAPmbxnn4nYBPigG10siFVOQRWSwm7aF8QB9za9cyojU2k2G8NtyXedenfF1UXEfDjaPhbMS7gRGT4dQPNsrr+YL215bq8SlJM9WZBtvMKIye7967KIu6DUm8UZ/ZN3j0u8HYPWEn+gbwyyXhioUpSWrGLVFqMAaBtj/Gso0L7inCL0HODXU/+p54UE6Uf2VDoJIVVxE9te4vPbqXuDiycGvE4I5F52CHGAMK1cPSg4MpSIQKBgQD2GXQQWVG3uJDMHSrDf6hw/xPHER6XGQ78+Jxl5sXYZNb9Ar6ZHGYsleskOzyU3LNJee+oItrx/HXukkhdsUkeZb/ti9XMCXPKGL8XI+UCqyYpnBVuzIonGaAvbZJTKVHqyPOM1F5xRM/lv/dchkzBWqoaBUwG1IEiL19XH+oHyQKBgQDPWnb0AVpO6dN27l6AIT+qCmlLXKBAASSuurH6t6FFzd2mjUgCsmH17KYkiwO8COJ1FvUkoeNLYBDsfA+/Ko8BXzt1LEjXoYqfCjNXIuTTy8lpjqQuNF3Ql7oOevRJXnoeOQ04By9UOP4d58N0mEEfRch1OX6vCsKUOYgMFAB1YQKBgQCBA8UB0SFy9DIMn3nMtX7jhgWjRYlI4x0lZ1vuW/X6RJskVqz+7ZFu7EUyYE+ZJr5i1aba+TLYy2Yz5MJFQ+y2H9dnO/igF5B5MVH0Wp/zLzA5fhcKV/ZRGzELzCB6sl28fQ6ZFLhSHyXyJxoRimJwtwwXyhEaP4tXFYigzx1MaQKBgCgvUxBU1simXjoVVjEkwG7W17MoP1JIJnDKc8WwIswhaoxlowgKxBtiAozgeBfP7PteOKIh0agA9SavoGme+Nn+N8qsi21mvDO4SVzgwVIek2kmoMDnmyrazM8TmxZA/g+vZNVv5wc+iFkJWoLVIwHJh2DYhKmtvyn0wF3+3lvhAoGBALwOWp4LsRWasoKyc6AvZlL05X7ra8yHtx3OLYxPKABXJz+0PmxRbutkaaOIdT73xBOkvEy134/Sz576FeVCyxUfMwCQn6BVLPplnT64ctSVCuk7hoKcAHzc6/dx8iol7MEXsAfoD6Hhl6nHebEJMuUSQPlq84s1GI4tp28wB/h8",
    "privateJsonWebKeyData": {
      "kty": "RSA",
      "use": "enc",
      "alg": "RSA-OAEP-384",
      "d":
          "BRC5E-C8goRUfIe3OdSRaxGqU65DVjwZB_TiCxOWlytqoENvn-J5jZ36ITYSVU1qNVPfGC8gD0weEZKI4TdLNr8bZouKW0789BtqAagAPmbxnn4nYBPigG10siFVOQRWSwm7aF8QB9za9cyojU2k2G8NtyXedenfF1UXEfDjaPhbMS7gRGT4dQPNsrr-YL215bq8SlJM9WZBtvMKIye7967KIu6DUm8UZ_ZN3j0u8HYPWEn-gbwyyXhioUpSWrGLVFqMAaBtj_Gso0L7inCL0HODXU_-p54UE6Uf2VDoJIVVxE9te4vPbqXuDiycGvE4I5F52CHGAMK1cPSg4MpSIQ",
      "n":
          "x1WMJlMHjU0Ic8gV6Xylk5o40GFOkcEN8Gw33uTMVRWphbACqZscvYpT2CQN0Lsnmcn-goC9I7WUT30ZzkKWiSDcYTfhiley2P4dfIhpDVhB2-EotqiG3BSxtmlQPM4bsEztlrx7p9MWN4ycZ0Ckfc235fUkHBrTIEonjIzwArzpLejRoUjpcdZVw_1-E_DK9Zo0bbiUsCFbc8hKPoAxa18V7NtRazHyIiQeGtLqI3naXa43qGTuqfhVxSWyJD_jV5eBGv1Kx4aeUEFHDAYAC5MuOTXtuSyiDEUV1gq-89HYCD1DmFPV0VR0J7nwAXSBzpmhEvYoJfgr4F-gwTvQKQ",
      "e": "AQAB",
      "p":
          "9hl0EFlRt7iQzB0qw3-ocP8TxxEelxkO_PicZebF2GTW_QK-mRxmLJXrJDs8lNyzSXnvqCLa8fx17pJIXbFJHmW_7YvVzAlzyhi_FyPlAqsmKZwVbsyKJxmgL22SUylR6sjzjNRecUTP5b_3XIZMwVqqGgVMBtSBIi9fVx_qB8k",
      "q":
          "z1p29AFaTunTdu5egCE_qgppS1ygQAEkrrqx-rehRc3dpo1IArJh9eymJIsDvAjidRb1JKHjS2AQ7HwPvyqPAV87dSxI16GKnwozVyLk08vJaY6kLjRd0Je6Dnr0SV56HjkNOAcvVDj-HefDdJhBH0XIdTl-rwrClDmIDBQAdWE",
      "dp":
          "gQPFAdEhcvQyDJ95zLV-44YFo0WJSOMdJWdb7lv1-kSbJFas_u2RbuxFMmBPmSa-YtWm2vky2MtmM-TCRUPsth_XZzv4oBeQeTFR9Fqf8y8wOX4XClf2URsxC8wgerJdvH0OmRS4Uh8l8icaEYpicLcMF8oRGj-LVxWIoM8dTGk",
      "dq":
          "KC9TEFTWyKZeOhVWMSTAbtbXsyg_UkgmcMpzxbAizCFqjGWjCArEG2ICjOB4F8_s-144oiHRqAD1Jq-gaZ742f43yqyLbWa8M7hJXODBUh6TaSagwOebKtrMzxObFkD-D69k1W_nBz6IWQlagtUjAcmHYNiEqa2_KfTAXf7eW-E",
      "qi":
          "vA5anguxFZqygrJzoC9mUvTlfutrzIe3Hc4tjE8oAFcnP7Q-bFFu62Rpo4h1PvfEE6S8TLXfj9LPnvoV5ULLFR8zAJCfoFUs-mWdPrhy1JUK6TuGgpwAfNzr93HyKiXswRewB-gPoeGXqcd5sQky5RJA-WrzizUYji2nbzAH-Hw"
    },
    "publicSpkiKeyData":
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx1WMJlMHjU0Ic8gV6Xylk5o40GFOkcEN8Gw33uTMVRWphbACqZscvYpT2CQN0Lsnmcn+goC9I7WUT30ZzkKWiSDcYTfhiley2P4dfIhpDVhB2+EotqiG3BSxtmlQPM4bsEztlrx7p9MWN4ycZ0Ckfc235fUkHBrTIEonjIzwArzpLejRoUjpcdZVw/1+E/DK9Zo0bbiUsCFbc8hKPoAxa18V7NtRazHyIiQeGtLqI3naXa43qGTuqfhVxSWyJD/jV5eBGv1Kx4aeUEFHDAYAC5MuOTXtuSyiDEUV1gq+89HYCD1DmFPV0VR0J7nwAXSBzpmhEvYoJfgr4F+gwTvQKQIDAQAB",
    "publicJsonWebKeyData": {
      "kty": "RSA",
      "use": "enc",
      "alg": "RSA-OAEP-384",
      "n":
          "x1WMJlMHjU0Ic8gV6Xylk5o40GFOkcEN8Gw33uTMVRWphbACqZscvYpT2CQN0Lsnmcn-goC9I7WUT30ZzkKWiSDcYTfhiley2P4dfIhpDVhB2-EotqiG3BSxtmlQPM4bsEztlrx7p9MWN4ycZ0Ckfc235fUkHBrTIEonjIzwArzpLejRoUjpcdZVw_1-E_DK9Zo0bbiUsCFbc8hKPoAxa18V7NtRazHyIiQeGtLqI3naXa43qGTuqfhVxSWyJD_jV5eBGv1Kx4aeUEFHDAYAC5MuOTXtuSyiDEUV1gq-89HYCD1DmFPV0VR0J7nwAXSBzpmhEvYoJfgr4F-gwTvQKQ",
      "e": "AQAB"
    },
    "plaintext": "aWd1bGEgaW1wZXJkaWV0LCBpZCBzdXM=",
    "ciphertext":
        "EBgBbGWO+jDsPxENuOMS2x4cTuVD/pOBnDOlAdYIH4dxdCaJQAS5qxPrGmpXuEQGr7rO99FGfWnaYwkJkv9anc5Wwq2+OUdhuKxDoJ2EPOEu5IH7PxI/CiEsYgnipPyrXzqQWQqL+gR8pJh0KCMyJXB/qhhUFuQFec5mSAZ6nrrPM+NdIVx8SMQJWrD0pF7g7r/RysBk9EZatKjxMcKwgq4HQhqqM28NKOPmmsJB5NylLZc82aXE+GxqeeBZewbZnnHe4Ssihgd/1oZWnmsUtw+CIoOc+0QcOnl4NjvL6Cdf+lfXJoa6CW2urGrBvTveWfavJkAS3R0zNncQ1VFztw==",
    "importKeyParams": {"hash": "sha-384"},
    "encryptDecryptParams": {
      "label": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
    }
  },
  {
    "name":
        "RSA-OAEP-384/label generated on chrome/linux at 2020-01-21T23:24:43",
    "privatePkcs8KeyData":
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDkBGEC4z6LmSfC1vhbia9N4+562nBG081KcKrQZgQbCwxHk2SKFyCoCDeL+1TBTwv6KPuunVefNOjBGkbfPNosTftS3Glc9+PpjW9bic0LUNcnPAMNnkYV80Hz+NRbRmvPzs6mjTRdNckxjZ/HXqEciZ6jzqdXbRxb/x3mXNeoi2qUc/LOHgh4RHvzu4t4qGcgdj0ecW4w1Soghhz1e+nE3k+3mEntfP9xTAf4wDNJOp/22u+B60Lqrp3TXFhXyd7jH2Pt+w31hN4Z5iHJTnDbhSsAo3chVK4ym/SXMPNigFOm3kgBIH3My8x4k4Czn0PSiD/xVCq4KAlMuxtjRiFzAgMBAAECggEAbKWnggQ8y7C9EOp0qc1X0jHu8uv9vsnyUmuQAL/zad1gSwSwzdnKTjaoHROzZW7gYqE/l4rScwJ3e3elWH666Ix52hg7PjjCCQnDC2eEY8Vv13qRa95EP/ZKsVEaAqnx+jFtJ1A2KMnVpb55aTquYxYyGJSCCTbs4esUWK1Zdy2cqCnUYFJL40u/LgQiQDoGpsnKvJutMezQi7QlfgElVLrLrjlD8z8sxsKeBYjoJHu/8QQJbR9XzOs/wVKUHKfdhKWH7wsd0I1391CHR2I4kzt8JFbXh+5PUcB/m240rFPJjMpm2ZTy503RqEccH357pdsdNunQ5L/XIJMBVnF8WQKBgQD9YYTpxFFSnx1s9HOuFa8o3pb+zUHen0HwBK/Uwoc6o+8p+Ag9AyRILeL71El7aal4BwHRcGbul0ffTvbYxsDBbwkz8zhwGxrSSeneQhsX2pYKXKPwMBMnhIfAlIvbqnZep499gwzWei5ZCnwR+mFxYUJyy1hIvPQrsB/th4GymwKBgQDmX75bGAzfpP4ISgXEWv+2W6znbJ3eitUObyvWfBWEnpQKcezGhzM4+rEUgMfptZHuaxIqyUIl+xwKFbjYz6OaZLxWdscV7CCpl08rHIRlhbDALWYz64XYaZ6mhwSY7P9nOeo7/yZ54j6cFBvyPux/aEC44PtfOFc0KF8B200uCQKBgEIL+HRi6vvJZAcxlTHMjzLtCpjycfgQtURWRGsGJe/AKahb8fHNbtittVwFUv4rZbRWxz+LuBj7MA3ibG/HJxmE0vZKsOxv9EbaY26+9ob6QGAFE+qY7XVAk448alRhE6fKr5l83ozNnmUxWXPqOxotyv9XR/T15AO7TidBSip/AoGAKkqDSHfGzTudwunL2zsVXGXB/Q4MgTEdYbP46TwIOztdU/mMDPn+5kPnRCtMB9RkQM95G0+tDAnoINXSBENB9nLtvDW74INjj56OUwy+JWEAjJcI/xkKjir9i/aXWnePf2S7Yl45swBcnAx5AOSaR91cnFP48YcHQzTyFAYtSfkCgYEA43UtAqKckTZdYpRwLcmWpAgv3gHej89woCCcp8L/u31nWmOd/jGuTc4qYr0DXUUOW1WNGoyS8qt4jFkA2Y8jypp1ymRf9Z0bxYtRJA+qPk4OsXnNQvQP2+GoQqrDDiCqd1n9Li0n43yQ/0bjqkiOptAki0/qCK8zgloHoJaUkSw=",
    "privateJsonWebKeyData": {
      "kty": "RSA",
      "alg": "RSA-OAEP-384",
      "d":
          "bKWnggQ8y7C9EOp0qc1X0jHu8uv9vsnyUmuQAL_zad1gSwSwzdnKTjaoHROzZW7gYqE_l4rScwJ3e3elWH666Ix52hg7PjjCCQnDC2eEY8Vv13qRa95EP_ZKsVEaAqnx-jFtJ1A2KMnVpb55aTquYxYyGJSCCTbs4esUWK1Zdy2cqCnUYFJL40u_LgQiQDoGpsnKvJutMezQi7QlfgElVLrLrjlD8z8sxsKeBYjoJHu_8QQJbR9XzOs_wVKUHKfdhKWH7wsd0I1391CHR2I4kzt8JFbXh-5PUcB_m240rFPJjMpm2ZTy503RqEccH357pdsdNunQ5L_XIJMBVnF8WQ",
      "n":
          "5ARhAuM-i5knwtb4W4mvTePuetpwRtPNSnCq0GYEGwsMR5NkihcgqAg3i_tUwU8L-ij7rp1XnzTowRpG3zzaLE37UtxpXPfj6Y1vW4nNC1DXJzwDDZ5GFfNB8_jUW0Zrz87Opo00XTXJMY2fx16hHImeo86nV20cW_8d5lzXqItqlHPyzh4IeER787uLeKhnIHY9HnFuMNUqIIYc9XvpxN5Pt5hJ7Xz_cUwH-MAzSTqf9trvgetC6q6d01xYV8ne4x9j7fsN9YTeGeYhyU5w24UrAKN3IVSuMpv0lzDzYoBTpt5IASB9zMvMeJOAs59D0og_8VQquCgJTLsbY0Yhcw",
      "e": "AQAB",
      "p":
          "_WGE6cRRUp8dbPRzrhWvKN6W_s1B3p9B8ASv1MKHOqPvKfgIPQMkSC3i-9RJe2mpeAcB0XBm7pdH30722MbAwW8JM_M4cBsa0knp3kIbF9qWClyj8DATJ4SHwJSL26p2XqePfYMM1nouWQp8EfphcWFCcstYSLz0K7Af7YeBsps",
      "q":
          "5l--WxgM36T-CEoFxFr_tlus52yd3orVDm8r1nwVhJ6UCnHsxoczOPqxFIDH6bWR7msSKslCJfscChW42M-jmmS8VnbHFewgqZdPKxyEZYWwwC1mM-uF2GmepocEmOz_ZznqO_8meeI-nBQb8j7sf2hAuOD7XzhXNChfAdtNLgk",
      "dp":
          "Qgv4dGLq-8lkBzGVMcyPMu0KmPJx-BC1RFZEawYl78ApqFvx8c1u2K21XAVS_itltFbHP4u4GPswDeJsb8cnGYTS9kqw7G_0Rtpjbr72hvpAYAUT6pjtdUCTjjxqVGETp8qvmXzejM2eZTFZc-o7Gi3K_1dH9PXkA7tOJ0FKKn8",
      "dq":
          "KkqDSHfGzTudwunL2zsVXGXB_Q4MgTEdYbP46TwIOztdU_mMDPn-5kPnRCtMB9RkQM95G0-tDAnoINXSBENB9nLtvDW74INjj56OUwy-JWEAjJcI_xkKjir9i_aXWnePf2S7Yl45swBcnAx5AOSaR91cnFP48YcHQzTyFAYtSfk",
      "qi":
          "43UtAqKckTZdYpRwLcmWpAgv3gHej89woCCcp8L_u31nWmOd_jGuTc4qYr0DXUUOW1WNGoyS8qt4jFkA2Y8jypp1ymRf9Z0bxYtRJA-qPk4OsXnNQvQP2-GoQqrDDiCqd1n9Li0n43yQ_0bjqkiOptAki0_qCK8zgloHoJaUkSw"
    },
    "publicSpkiKeyData":
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5ARhAuM+i5knwtb4W4mvTePuetpwRtPNSnCq0GYEGwsMR5NkihcgqAg3i/tUwU8L+ij7rp1XnzTowRpG3zzaLE37UtxpXPfj6Y1vW4nNC1DXJzwDDZ5GFfNB8/jUW0Zrz87Opo00XTXJMY2fx16hHImeo86nV20cW/8d5lzXqItqlHPyzh4IeER787uLeKhnIHY9HnFuMNUqIIYc9XvpxN5Pt5hJ7Xz/cUwH+MAzSTqf9trvgetC6q6d01xYV8ne4x9j7fsN9YTeGeYhyU5w24UrAKN3IVSuMpv0lzDzYoBTpt5IASB9zMvMeJOAs59D0og/8VQquCgJTLsbY0YhcwIDAQAB",
    "publicJsonWebKeyData": {
      "kty": "RSA",
      "alg": "RSA-OAEP-384",
      "n":
          "5ARhAuM-i5knwtb4W4mvTePuetpwRtPNSnCq0GYEGwsMR5NkihcgqAg3i_tUwU8L-ij7rp1XnzTowRpG3zzaLE37UtxpXPfj6Y1vW4nNC1DXJzwDDZ5GFfNB8_jUW0Zrz87Opo00XTXJMY2fx16hHImeo86nV20cW_8d5lzXqItqlHPyzh4IeER787uLeKhnIHY9HnFuMNUqIIYc9XvpxN5Pt5hJ7Xz_cUwH-MAzSTqf9trvgetC6q6d01xYV8ne4x9j7fsN9YTeGeYhyU5w24UrAKN3IVSuMpv0lzDzYoBTpt5IASB9zMvMeJOAs59D0og_8VQquCgJTLsbY0Yhcw",
      "e": "AQAB"
    },
    "plaintext":
        "c2wKY29tbW9kbyBhdWN0b3IuIEludGVnZXIgZXQgZXN0IGV1IG5lcXVlIHBlbGxlbnRlc3F1ZSA=",
    "ciphertext":
        "UhoSP2C7gV9g3XBAwiMQtplf+N4FGlZYxMbP2OyO5ENZG6hpdoW2xlTOKqw883rAxStRmREfmZToRSXvw2sOuH0Un2xKthIkjQSPbd3NSd1qYHDd+qJgy7XXxhjAdAd8g3VvkZUJQG/nrNSOMzD5Ypud7huTp6xL0OHbn38Ws6JcESDyZwCwicbgr0PWp6T7Gp4kVZtSnQ2ag1P/b7gwhCci/foCLREezHHiVFWbM1+1U8q6Dciq3LLsZyLrx4ImcEB0qyXzHKXA6QAGhUhglNbPDPYcv8XwW2wVbCUyIkfY7FSMbVZjV/QdHVvQBMZOfyGNu9BrBmygh7V05C9bXQ==",
    "importKeyParams": {"hash": "sha-384"},
    "encryptDecryptParams": {
      "label": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
    }
  },
  {
    "name":
        "RSA-OAEP-384/label generated on firefox/linux at 2020-01-21T23:24:50",
    "privatePkcs8KeyData":
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCfHHyi9iHA01z4DM9Z3Ai17eqOIazyMP/GNfzxpaQ8JWPg+WK2uCaSr20MzkQBhVJpQrO8hCC10RXP2VPK9rUmo1E8J+guU/yyLMoS2jDL3FVuGw9kqcBMG8k5M4qbqSaEMfXXlxWbEGfhjlFytCBeBDOQ7RphA1cYqKfQrcOUr91U3M0VmMz2p5c7OLCNdg6iAS2AG+nCEkz00xofqN+/uo+3cAbq6Oyjgj/ma5YNOz/CarxHMOkMiUwh0G0ukr3KnCq0JlEB7gxurWTVy7FzNjRj8zpuqKYhmwzXbtNRK+zDbTX5/0fjaUQScZipJQzTr5p17yum8BIXnAj+PjqzAgMBAAECggEAQxHFggYBlWAjRNZVg1nqfBHlePM+DTtVXc59KLl7gPT75KYLE92NOPDkpWy/Iur5obBBxnnlte6EZMCF/zy+gKKASDzENN8nWk3iAk9iGVTv2AFlHDgn/I0L5eZRi6siNsA+kpm3vE0OlPgiYhkGucrIl9MydulrCdRyJNdSZbaP9kHhWfwBTu/Iqx3lX5AWjj4vRZO2sTbfqFPSZ6Ac09hm9Se1E8kXNCTHUwkKI5oVkNtf0oOAcmEWYULjxyWSTdiLmIwXfqOWAu7OZX6WhTlLQZBIaMLPoP9MEIrfrgpCtVs57zUBKZ1UTh+mgnDctshSzvbZdUX4Cvj41cR6iQKBgQDQmX5Mt5ujUJh1acnml5Xm+O4QVQC1syV6wGw3vZ3wevf3zbfGP0FxKN4w3nlNZuFeQRdwwnbJ95nhgHQCOgugH6+ZLmXCVk3rlHVU2LaqPVxPijjndAsog2pFrF2SxhxwRzgdNHPIdbbbMD1w1teZLCqDKXCKD6UiVQJQQD7LiwKBgQDDRDHmOXS00plgvZeKLW0BKu/4LqHmAATRlPsNvPpIWvmj2RuDBViVu//weIoQJ0hcRbU9IM80KQQcjLZKn3uuXWnQfoD5BymGmgnwQ/uKKUhO3TBJP5hgXnoywwxR86Hbk0vW5QP6BcUS41zMauU/8uxqPRd+EMkpTrpva8jSeQKBgEXZcAJOZQ5NuY9vag0N60MZTdYoMIGnSECPWG1d0Borgwb2WrhGjCpRLf2dMW8qqQJ/t1Kpu08r2to4wh/Qwf3PPmSDtc1aSuM8pgFQQ/JDc7qqpR1TrTzWrGpCKl8weWtbXb3hx3dze1RwFdLIDg+bS2z6HlYMoRYa8xheOui7AoGADzmkAmV8ehTprKdbx4RfOXYVm+5W5U4fEhBhuuJ/SWD+kg39nSuvio1MGX3slfHaLIeq6AdE4LZKAcfe9taUmDXkaENU3xX14O7l03wZgt5RKwUIHM3+nZUARjD7JvCuMCa+BRV6R+ZnRV/A/pdfJKtWT7pPuJ6qcLQYyVNIJ1ECgYEAt0HAm+abNJAj2OlyOXf60f6hLxBT6v9CBnXu4ar2t07CpG6eDbW1SmhNYLEIwX5nAj1mzjyp5IkondcINVzlbou8a3pU+bLGW8h6wvSyp19bPUGrNDderxTll3brNTtNAQChl2k600JtMKD85kRa4IBnE9FDppGbCGZqM306SBM=",
    "privateJsonWebKeyData": {
      "kty": "RSA",
      "alg": "RSA-OAEP-384",
      "d":
          "QxHFggYBlWAjRNZVg1nqfBHlePM-DTtVXc59KLl7gPT75KYLE92NOPDkpWy_Iur5obBBxnnlte6EZMCF_zy-gKKASDzENN8nWk3iAk9iGVTv2AFlHDgn_I0L5eZRi6siNsA-kpm3vE0OlPgiYhkGucrIl9MydulrCdRyJNdSZbaP9kHhWfwBTu_Iqx3lX5AWjj4vRZO2sTbfqFPSZ6Ac09hm9Se1E8kXNCTHUwkKI5oVkNtf0oOAcmEWYULjxyWSTdiLmIwXfqOWAu7OZX6WhTlLQZBIaMLPoP9MEIrfrgpCtVs57zUBKZ1UTh-mgnDctshSzvbZdUX4Cvj41cR6iQ",
      "n":
          "nxx8ovYhwNNc-AzPWdwIte3qjiGs8jD_xjX88aWkPCVj4Plitrgmkq9tDM5EAYVSaUKzvIQgtdEVz9lTyva1JqNRPCfoLlP8sizKEtowy9xVbhsPZKnATBvJOTOKm6kmhDH115cVmxBn4Y5RcrQgXgQzkO0aYQNXGKin0K3DlK_dVNzNFZjM9qeXOziwjXYOogEtgBvpwhJM9NMaH6jfv7qPt3AG6ujso4I_5muWDTs_wmq8RzDpDIlMIdBtLpK9ypwqtCZRAe4Mbq1k1cuxczY0Y_M6bqimIZsM127TUSvsw201-f9H42lEEnGYqSUM06-ade8rpvASF5wI_j46sw",
      "e": "AQAB",
      "p":
          "0Jl-TLebo1CYdWnJ5peV5vjuEFUAtbMlesBsN72d8Hr39823xj9BcSjeMN55TWbhXkEXcMJ2yfeZ4YB0AjoLoB-vmS5lwlZN65R1VNi2qj1cT4o453QLKINqRaxdksYccEc4HTRzyHW22zA9cNbXmSwqgylwig-lIlUCUEA-y4s",
      "q":
          "w0Qx5jl0tNKZYL2Xii1tASrv-C6h5gAE0ZT7Dbz6SFr5o9kbgwVYlbv_8HiKECdIXEW1PSDPNCkEHIy2Sp97rl1p0H6A-QcphpoJ8EP7iilITt0wST-YYF56MsMMUfOh25NL1uUD-gXFEuNczGrlP_Lsaj0XfhDJKU66b2vI0nk",
      "dp":
          "RdlwAk5lDk25j29qDQ3rQxlN1igwgadIQI9YbV3QGiuDBvZauEaMKlEt_Z0xbyqpAn-3Uqm7Tyva2jjCH9DB_c8-ZIO1zVpK4zymAVBD8kNzuqqlHVOtPNasakIqXzB5a1tdveHHd3N7VHAV0sgOD5tLbPoeVgyhFhrzGF466Ls",
      "dq":
          "DzmkAmV8ehTprKdbx4RfOXYVm-5W5U4fEhBhuuJ_SWD-kg39nSuvio1MGX3slfHaLIeq6AdE4LZKAcfe9taUmDXkaENU3xX14O7l03wZgt5RKwUIHM3-nZUARjD7JvCuMCa-BRV6R-ZnRV_A_pdfJKtWT7pPuJ6qcLQYyVNIJ1E",
      "qi":
          "t0HAm-abNJAj2OlyOXf60f6hLxBT6v9CBnXu4ar2t07CpG6eDbW1SmhNYLEIwX5nAj1mzjyp5IkondcINVzlbou8a3pU-bLGW8h6wvSyp19bPUGrNDderxTll3brNTtNAQChl2k600JtMKD85kRa4IBnE9FDppGbCGZqM306SBM"
    },
    "publicSpkiKeyData":
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnxx8ovYhwNNc+AzPWdwIte3qjiGs8jD/xjX88aWkPCVj4Plitrgmkq9tDM5EAYVSaUKzvIQgtdEVz9lTyva1JqNRPCfoLlP8sizKEtowy9xVbhsPZKnATBvJOTOKm6kmhDH115cVmxBn4Y5RcrQgXgQzkO0aYQNXGKin0K3DlK/dVNzNFZjM9qeXOziwjXYOogEtgBvpwhJM9NMaH6jfv7qPt3AG6ujso4I/5muWDTs/wmq8RzDpDIlMIdBtLpK9ypwqtCZRAe4Mbq1k1cuxczY0Y/M6bqimIZsM127TUSvsw201+f9H42lEEnGYqSUM06+ade8rpvASF5wI/j46swIDAQAB",
    "publicJsonWebKeyData": {
      "kty": "RSA",
      "alg": "RSA-OAEP-384",
      "n":
          "nxx8ovYhwNNc-AzPWdwIte3qjiGs8jD_xjX88aWkPCVj4Plitrgmkq9tDM5EAYVSaUKzvIQgtdEVz9lTyva1JqNRPCfoLlP8sizKEtowy9xVbhsPZKnATBvJOTOKm6kmhDH115cVmxBn4Y5RcrQgXgQzkO0aYQNXGKin0K3DlK_dVNzNFZjM9qeXOziwjXYOogEtgBvpwhJM9NMaH6jfv7qPt3AG6ujso4I_5muWDTs_wmq8RzDpDIlMIdBtLpK9ypwqtCZRAe4Mbq1k1cuxczY0Y_M6bqimIZsM127TUSvsw201-f9H42lEEnGYqSUM06-ade8rpvASF5wI_j46sw",
      "e": "AQAB"
    },
    "plaintext": "b2RvCm1vbGVzdGllIG51bGxhLiBVdCBvZGlvIG1hZ25hLCBsdWM=",
    "ciphertext":
        "lAHrVNDEbmcxiI7JqaZxrr4JUnYMuuitshbvr+6NmUnLjul1wWNgeyFggZ8sCqhslsgD03zaNJHJ5pKgrAbCM4EEP+W1f1qkH35qKAaGAsU8oiDXESBojIp335TqUeqRHhY1t8T1TX6VFFMpIrUkvhTFk6H9dTNC0U14lY5SNlbzJDPX76sAbL6u6J6O2aNn/sa9q5DueCHrenutN28J22+7XOqWr/mfUo9E0j0/etfmbFvcAckdGrvhg+o6XgOiuWwK1lNYwKObZaJDPGy+/NM6qms6vZo4OTmH00AoUBe1QH029yDJIh4+7JKeVIXMrBWOhnfgy1wz9VphHRSeLw==",
    "importKeyParams": {"hash": "sha-384"},
    "encryptDecryptParams": {
      "label": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
    }
  },
];
