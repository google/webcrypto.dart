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

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';
import '../utils/utils.dart';
import '../utils/testrunner.dart';

/// Utility to hold both [HkdfSecretKey] and [rawKeyData], such that we can
/// fake an implementation of `exportPrivaterawKey` for [TestRunner].
class _ExportableHkdfSecretKey {
  final HkdfSecretKey hkdfSecretKey;
  final List<int> rawKeyData;
  _ExportableHkdfSecretKey(this.hkdfSecretKey, this.rawKeyData);
}

final runner = TestRunner.symmetric<_ExportableHkdfSecretKey>(
  algorithm: 'HKDF',
  importPrivateRawKey: (keyData, keyImportParams) async {
    return _ExportableHkdfSecretKey(
      await HkdfSecretKey.importRawKey(keyData),
      keyData,
    );
  },
  // Not really support by [HkdfSecretKey] but required by [TestRunner].
  exportPrivateRawKey: (key) async => key.rawKeyData,
  importPrivatePkcs8Key: null, // not supported
  exportPrivatePkcs8Key: null,
  importPrivateJsonWebKey: null,
  exportPrivateJsonWebKey: null,
  generateKey: (generateKeyPairParams) async {
    final rawKeyData = Uint8List(generateKeyPairParams['length']);
    fillRandomBytes(rawKeyData);
    return _ExportableHkdfSecretKey(
      await HkdfSecretKey.importRawKey(rawKeyData),
      rawKeyData,
    );
  },
  deriveBits: (key, length, deriveParams) => key.hkdfSecretKey.deriveBits(
    length,
    hashFromJson(deriveParams),
    bytesFromJson(deriveParams, 'salt')!,
    bytesFromJson(deriveParams, 'info')!,
  ),
  testData: _testData,
);

void main() {
  test('generate HkdfSecretKey test case', () async {
    await runner.generate(
      generateKeyParams: {'length': 17},
      importKeyParams: {},
      deriveParams: {
        'hash': hashToJson(Hash.sha512),
        'salt': bytesToJson(List.generate(32, (i) => (i + i) % 256)),
        'info': bytesToJson(List.generate(12, (i) => (i + i) % 256)),
      },
      minDeriveLength: 512,
      maxDeriveLength: 512,
    );
  });

  runner.runTests();
}

// Allow single quotes for hardcoded testData written as JSON:
// ignore_for_file: prefer_single_quotes
final _testData = [
  {
    "name": "SHA-256/4096 generated on boringssl/linux at 2020-01-26T20:39:09",
    "privateRawKeyData":
        "A+j551PL23NFSuxvIbWfCeu/WgbHrkzR/aLKe7reJiOn9wEgucQfX6xTSj0ILtxp/XqQ6bc/zA1+aJsNKij7Kx+vTejA34nKtoVGsS9Y/7DaWWmNRPV8K3znImcj2yzmQM9Tpc7ILrarTWfW+LEl7h8WQ6fBxCSsd0WMBgnrJlQZcJWOEMOEbDy48SWpzAISAqdEBuyP5abCir8vFRW+5IKyt6UngRUCogFxL/8fFtmiNVpCG+qzZsk3JoY3Ss2d4HZdnAeKu2GAOmgdFUrf9RM9mEiEzk6bb7tqjRkyV/EeU28gRChCMJDWTil0cqwMzNseEvhwtfJ2QRqUAWOWb8nyAgx2tQw9R8hGE8g/YuSa2HD9BIM32T0wWdI8P9AtOAON3KgEIQgCVZDfnXsVHyy/pw8Kd5xu6//gtANNHAfOWDXacZZRmqRlsQZP2lWlwirSH5navcxZp5aw49HTyVbkDh9qVtu/Pjcg0i3tSSV3h+qsqJUCqnTAKQC7wpmVka59B9gAjo7u8U/qBcywdjVGF0nU5zcz8c0aR1PN+pBYUPa1Kyvh0D0cZkDQswFV6aEiXSfazbTHL0QwIc/MIT515/yn1zfZzgLLo4pO1fJi1Vebvg0plhXvkFVIK1cMHaXEjcvtn2tdHInWChvZwm/8tO/hRy5xtQu1YHR+rQE=",
    "derivedBits":
        "baAazXqtXUtFDJNsnbg1kATb7UFSODf3jT6UdIo6EGHRqNPQrGDMeTKns/mKN/gm3QL0Gbn1jwqUL1AcTyuR4EZcds6Zu7zZeUe2Ekn4B476nP5DH5Kn6hPCOIxCs7nY3ehPWflTpkyjl+hURDz+EFCb2/neP2/B/7P15ws/kJptTkDricL+r4sXw0QbaLFWjTRXyYbycYY5AdVQiVjT6oPGg4rye3JKYDwcaFRYl5sWoEvrusi3a0MN0m34pI/M3o2FzLgbaaYTNX27ek4O5RYflmrjha5k2c7sCp15sJ2EFeNMTRosvfa0/dLsh2NxDGFnfM3SRBZPUcvDhPSPT1EFhsvGXtZWf3MgceVO5YrxM6mJ2gT+Jdof7Th061zV7iRsbwb01VUlv1XLzSUD8B+y1oOEW+CHaKeoea9ZKDShmfiMs0P1LfyCzFW/S48JMLCr6xOcBt2FEy6pXR3MDejGhUxRJb4bsDdy1kPUvnnUXqCRG+J1kz0ecaBHPABSqf7JE84JojTeYQnffgmNuUmRDt49BfOPwsIRuC657LZR/vqVSxDbCDU8SBX8yYbJGstbYjbWMBboylvh51oFCFKMl4gW/TYsmgnnbu8S1PYOibsrD3rajkQZnX+ajhRLZqQKPlumnl9ldH2eCtMdWJML00GbfikatdYqelI9mYE=",
    "derivedLength": 4096,
    "importKeyParams": {},
    "deriveParams": {
      "hash": "sha-256",
      "salt": "AAIEBggKDA4QEhQWGBocHiA=",
      "info":
          "AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD5AQkRGSEpMTlBSVFZYWlxeYGJkZmhqbG5wcnR2eHp8foCChIaIioyOkJKUlpianJ6goqSmqKqsrrCytLa4ury+wMLExsjKzM7Q0tTW2Nrc3uDi5Obo6uzu8PL09vj6/P4AAgQGCAoMDhASFBYYGhweICIkJigqLC4wMjQ2ODo8PkBCREZISkxOUFJUVlhaXF5gYmRmaGpsbnBydHZ4enx+gIKEhoiKjI6QkpSWmJqcnqCipKaoqqyusLK0tri6vL7AwsTGyMrMztDS1NbY2tze4OLk5ujq7O7w8vT2+Pr8/gACBAYICgwOEBIUFhgaHB4gIiQmKCosLjAyNDY4Ojw+QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6fH6AgoSGiIqMjpCSlJaYmpyeoKKkpqiqrK6wsrS2uLq8vsDCxMbIyszO0NLU1tja3N7g4uTm6Ors7vDy9Pb4+vz+AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD5AQkRGSEpMTlBSVFZYWlxeYGJkZmhqbG5wcnR2eHp8foCChIaIioyOkJKUlpianJ6goqSmqKqsrrCytLa4ury+wMLExsjKzM7Q0tTW2Nrc3uDi5Obo6uzu8PL09vj6/P4="
    }
  },
  {
    "name": "SHA-256/4096 generated on chrome/linux at 2020-01-26T20:39:16",
    "privateRawKeyData":
        "uf3nPq/+4GqnhG22+m7BeH9EmpwYT7tiG00BPGvudoyR3MSjHj1+XS6gtBvHYSvQn6b/AWXySlTSGW8ppmJTLhFG0FFA+nyTc0KX3QbhLI7fj/XgohVr7RKmH41OwTUqfSfrk/u0/SfAsIQMqZJmkA0Y4krAKdFmYWUVQKbtQVuFV88fN5A9fnAck0rDuboFcrWz7s57bi13vAeRYfdkb9jaq2/I2RcSUrLb0a1HspRPSybCnIsR4hmE4NOwxHz4qiM7iFBEVmTt4va832E+Yxy7cGkqwC6S1buqV1+4RfJUMABNC3JWu+qrDcLG2jzntp5gDbVMADhd5TinoPW9vn8EZDbqQdK6I+kap9xCvcL+xtdmm92k0l9O4E20p6Ok1UDq+ltZiuXrzZcXbwJEkcHXUHGGwWg5NqJne8WZ3W6LFLYsbzslrhrlboWYVICtnFjr/J8KfQQNaehzowIDFqujiG9VHUoKQlsl6TLgxUNqGf7RMynDSCvEEx9xkhUgD6Vsd78ewxmPUpNTI/5HB3B9tRp3EyObkJbazEm0b1+5k2P/IDHWrKcbkBoNh8rS8F3wW9uiWm9YK2u3IFSd26H6zp/q+ix7AtiByk0z8oBaP7iZHhFECZiOh9uR9ZYzO/B5Ocj0THUWppb+5w/NU5Vsjd9C9gJ5hFju7xz3mpY=",
    "derivedBits":
        "A8H41BTJ2GebTnf7/NhdVHYkmqhlT7qdf7Tbt6mGiRYagbBJ2enBsNBIeNnfV+J950kBst/nF+9CiutNF4770CxxzCev5NcJvts1rKEsPLfiCZJ2PhUsMA2kJIs0ZSsK+d9NaEGflL54ELW/Uef0Vf+wDWCof72PbqAsfS7Z0NqKpSuK6QbFAbWsXE8x8ZJqt8WpQ4dqCaHOc27zRw+b06R401NcDQ+Cx2+UbMYlQd87z9cARcSs8fMrAgvTe0MThCLLEfGBVzAdK3KgPxCo4+JyY3oVHhe+uTP5nXz/apD9gZwc/4DJasVVVxcfgjxcgXVuWGEkdoNHfDj3F4GbNO1M01/XHf3suOofKRl67EaqEf7eFDaVwqbKY4HHEGJgG06cS7qW50FbrNQeLLe5avD3/1WHRNXzniUinfvvKr533AMVX9UoSqEXZmLWwAhnoFu18Gn9QDB2z+e33NRbhMVv62Ao63q9MjQIEsOZtbsLu9KQnBC48aZ3u6IxfP9L6zDBj+OHHjKcjqLhWB53YuXqInMGlZ8iuMW0XzP2nJ7yf1w8qw/WHRjRpHXITA+/GjoVvfI4l0m2AAX6Q4CUDQszNKRQ6KVdqpe8rR8qwhd88oYBbJv5Bq8VBxzqghNDnSOt5NEGpQu37YFOJ/Iw17PqVWN9rAKrvtiwcpgAKYc=",
    "derivedLength": 4096,
    "importKeyParams": {},
    "deriveParams": {
      "hash": "sha-256",
      "salt": "AAIEBggKDA4QEhQWGBocHiA=",
      "info":
          "AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD5AQkRGSEpMTlBSVFZYWlxeYGJkZmhqbG5wcnR2eHp8foCChIaIioyOkJKUlpianJ6goqSmqKqsrrCytLa4ury+wMLExsjKzM7Q0tTW2Nrc3uDi5Obo6uzu8PL09vj6/P4AAgQGCAoMDhASFBYYGhweICIkJigqLC4wMjQ2ODo8PkBCREZISkxOUFJUVlhaXF5gYmRmaGpsbnBydHZ4enx+gIKEhoiKjI6QkpSWmJqcnqCipKaoqqyusLK0tri6vL7AwsTGyMrMztDS1NbY2tze4OLk5ujq7O7w8vT2+Pr8/gACBAYICgwOEBIUFhgaHB4gIiQmKCosLjAyNDY4Ojw+QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6fH6AgoSGiIqMjpCSlJaYmpyeoKKkpqiqrK6wsrS2uLq8vsDCxMbIyszO0NLU1tja3N7g4uTm6Ors7vDy9Pb4+vz+AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD5AQkRGSEpMTlBSVFZYWlxeYGJkZmhqbG5wcnR2eHp8foCChIaIioyOkJKUlpianJ6goqSmqKqsrrCytLa4ury+wMLExsjKzM7Q0tTW2Nrc3uDi5Obo6uzu8PL09vj6/P4="
    }
  },
  {
    "name": "SHA-256/4096 generated on firefox/linux at 2020-01-26T20:39:21",
    "privateRawKeyData":
        "Sv0tC8INLN+6ePqubU2gHeTh9ce87EPLa2hsqN1hZ3HVj87o5gfBp4rP3w9y8ieaPfXmsAGNF5uOW2Bz+HFRhfK3v5CCmBOeEshnfzMNebYH0kpsLR2JsxJeE24vszsn/VEguTw2+2GvkJwyUgU4QEIoYYfMpAa5U3Grc5yGoRVgNKBsJQeK/Rmzf9cszQW5kzBpvw7HpXMirgCLuTckSwltvo4kph4QfoElVCyZenjJH8lOUQGOW4Xc6u5dISs9tJyUiavAL4y+Pbqc0HDUuH3vzftJqmsscSJEiyXqnfZiUzbTOVWIv72FdYnEr7mWOiWc+tRbKUIA+J8y9QVh615FXtSsOOV2ObTWEQD4vScLLS0iLBaiEj7mOENNjzMjFOilzKjZgeyNmJWKpbULbdxmXZIAn7lbT5M04oKpl6CBB9LHAXLiR4vnWe5IWK07x6gyhpKXN9ZLF11aMDkgU69WLbfk1xXo+s/4YWTtIV5/G4Xu3YUYYX7cmptJ16ejCz5Wso4Tjy/dN1lAsImhugk/efKSFHOtJzjdHx23GAI6oKWP9i6GpQ0XASqmOGVsh5iUqprF/06yQrrlG6htObaQfSIDUrkvAC5ML1mB64qM0ykxApD+EGCM7U+bzhaMgkGoqYJ87icNbw7g9qUM8XbutKOEv2PUOpAQI8SsLtI=",
    "derivedBits":
        "5HNUVzwnRVZhMatfG2lg18HyRNcssaZSpbiCXBb4fNoC3auJBv9leK3bKz46zZKXTJktfh05wEY7GnAs9tvjV55ouDnsLguRaMqGRIPbegll22JwV22l24K4FF8Xajb/tryNaHHotHeEaYNsO6tjcsa+tmWLoYGtI4UiRo+3Ul3w6Zcp3AvCV9vhMWgoEYkJ02wK1i7hHEZQ//3iXXJrv+ZP2C1p7rkf1pGD62Lp2NFOHeXI/1nh76fC3DyKpraFZkBJrXL7XO4gUcJ78YpJess3DSiTVYIOmNAbF/NrkB3kzUr7pykuRdKdVejN4HAPYdJWaddV6mqXVY7yj+kyUPJNIM3OjnXiecO/9Fyl/FctnPPtPh+Pa6SxlnIt0uphqViFoiljJihZ1WTNHVpeb2F1bRl5LDaog8Ww+Po1e4+GWGaRGMV59Hzm7SGWSy2wO5kFluxfoiR2qJZnDDJ3352W/cxI2jUh4BKEVOnEQ9/R9rfpG7nzHuuTDnjnIy+pbjYW/CXGGNaKKIHEeHWcHuqVZAJzRDrJbu2WMI6fPt/PH5DXbDL/ffhWSjc7ktTO75qWFxmdrGZgZvMGB91BZIYUtHikok6KVl6nH/q8UAt2wG77xcDfshQ+qkA8TnqBjOy2xJewpi6T42Hy55Fy+i77MsUEgNs+qO+L/gQWhD0=",
    "derivedLength": 4096,
    "importKeyParams": {},
    "deriveParams": {
      "hash": "sha-256",
      "salt": "AAIEBggKDA4QEhQWGBocHiA=",
      "info":
          "AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD5AQkRGSEpMTlBSVFZYWlxeYGJkZmhqbG5wcnR2eHp8foCChIaIioyOkJKUlpianJ6goqSmqKqsrrCytLa4ury+wMLExsjKzM7Q0tTW2Nrc3uDi5Obo6uzu8PL09vj6/P4AAgQGCAoMDhASFBYYGhweICIkJigqLC4wMjQ2ODo8PkBCREZISkxOUFJUVlhaXF5gYmRmaGpsbnBydHZ4enx+gIKEhoiKjI6QkpSWmJqcnqCipKaoqqyusLK0tri6vL7AwsTGyMrMztDS1NbY2tze4OLk5ujq7O7w8vT2+Pr8/gACBAYICgwOEBIUFhgaHB4gIiQmKCosLjAyNDY4Ojw+QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6fH6AgoSGiIqMjpCSlJaYmpyeoKKkpqiqrK6wsrS2uLq8vsDCxMbIyszO0NLU1tja3N7g4uTm6Ors7vDy9Pb4+vz+AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD5AQkRGSEpMTlBSVFZYWlxeYGJkZmhqbG5wcnR2eHp8foCChIaIioyOkJKUlpianJ6goqSmqKqsrrCytLa4ury+wMLExsjKzM7Q0tTW2Nrc3uDi5Obo6uzu8PL09vj6/P4="
    }
  },
  {
    "name": "SHA-512/512 generated boringssl/linux at 2020-01-26T20:40:58",
    "privateRawKeyData": "bIK0uc4+qe3Q+TNbPKkQR9c=",
    "derivedBits":
        "020+xF88yWB4J1Et7mhZaYeDezK8Ok7fEgpu36e9msRFSjYyA18BS05+6VIITS1c8QP503D22iF2wdIKP9ZEBA==",
    "derivedLength": 512,
    "importKeyParams": {},
    "deriveParams": {
      "hash": "sha-512",
      "salt": "AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD4=",
      "info": "AAIEBggKDA4QEhQW"
    }
  },
  {
    "name": "SHA-512/512 generated chrome/linux at 2020-01-26T20:41:07",
    "privateRawKeyData": "7cQKupD1TqdM+8U7e87m2a4=",
    "derivedBits":
        "g0zMnJoIiehGOj1A2TUa6oTIuYt0IVUIShX0cRAEQ8YJukxuGB3xOCoMLdom4MQ1EQn9AqV5CDcuTTb+N6AYIA==",
    "derivedLength": 512,
    "importKeyParams": {},
    "deriveParams": {
      "hash": "sha-512",
      "salt": "AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD4=",
      "info": "AAIEBggKDA4QEhQW"
    }
  },
  {
    "name": "SHA-512/512 generated firefox/linux at 2020-01-26T20:41:12",
    "privateRawKeyData": "SMxqkH1UPUEhMje9B5yk9dU=",
    "derivedBits":
        "cb/K89cbcvK/QA/ceWLBpNUUG6CGe55681ayQZmizO7utSCIN1s8NYcaYRzXKrwpp0Ya456agdU9hCyg1stTFA==",
    "derivedLength": 512,
    "importKeyParams": {},
    "deriveParams": {
      "hash": "sha-512",
      "salt": "AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD4=",
      "info": "AAIEBggKDA4QEhQW"
    }
  }
];
