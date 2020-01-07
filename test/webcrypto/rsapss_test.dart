import 'package:webcrypto/webcrypto.dart';
import '../utils.dart';
import '../testrunner.dart';
import 'package:test/test.dart';

final runner = TestRunner<RsaPssPrivateKey, RsaPssPublicKey>(
  importPrivateRawKey: null, // not supported
  exportPrivateRawKey: null,
  importPrivatePkcs8Key: (keyData, keyImportParams) =>
      RsaPssPrivateKey.importPkcs8Key(keyData, hashFromJson(keyImportParams)),
  exportPrivatePkcs8Key: (key) => key.exportPkcs8Key(),
  // Not implemented (in FFI) yet
  // importPrivateJsonWebKey: (jsonWebKeyData, keyImportParams) =>
  //     RsaPssPrivateKey.importJsonWebKey(
  //         jsonWebKeyData, hashFromJson(keyImportParams)),
  // exportPrivateJsonWebKey: (key) => key.exportJsonWebKey(),
  importPublicRawKey: null, // not supported
  exportPublicRawKey: null,
  importPublicSpkiKey: (keyData, keyImportParams) =>
      RsaPssPublicKey.importSpkiKey(keyData, hashFromJson(keyImportParams)),
  exportPublicSpkiKey: (key) => key.exportSpkiKey(),
  // Not implemented (in FFI) yet
  // importPublicJsonWebKey: (jsonWebKeyData, keyImportParams) =>
  //     RsaPssPublicKey.importJsonWebKey(
  //         jsonWebKeyData, hashFromJson(keyImportParams)),
  // exportPublicJsonWebKey: (key) => key.exportJsonWebKey(),
  generateKeyPair: (generateKeyPairParams) => RsaPssPrivateKey.generateKey(
    generateKeyPairParams['modulusLength'],
    BigInt.parse(generateKeyPairParams['publicExponent']),
    hashFromJson(generateKeyPairParams),
  ),
  signBytes: (key, data, signParams) =>
      key.signBytes(data, signParams['saltLength']),
  signStream: (key, data, signParams) =>
      key.signStream(data, signParams['saltLength']),
  verifyBytes: (key, signature, data, verifyParams) =>
      key.verifyBytes(signature, data, verifyParams['saltLength']),
  verifyStream: (key, signature, data, verifyParams) =>
      key.verifyStream(signature, data, verifyParams['saltLength']),
);

void main() {
  test('generate RSA-PSS test case', () async {
    await runner.generate(
      generateKeyParams: {
        'hash': hashToJson(Hash.sha256),
        'modulusLength': 2048,
        'publicExponent': '65537',
      },
      importKeyParams: {'hash': hashToJson(Hash.sha256)},
      signVerifyParams: {'saltLength': 128},
      maxPlaintext: 80,
    );
  });

  runner.runAll([
    {
      "name": "test key generation",
      "generateKeyParams": {
        "hash": "sha-256",
        "modulusLength": 2048,
        "publicExponent": "65537"
      },
      "plaintext":
          "IFN1c3BlbmRpc3NlIHBsYWNlcmF0LCBhcmN1IGF0IGNvbnNlY3RldHVyCmFsaXF1ZXQsIGRvbG9yIGF1Z3VlIG1vbGVzdGllIA==",
      "importKeyParams": {"hash": "sha-256"},
      "signVerifyParams": {"saltLength": 128}
    },
    {
      "name": "generated on ffi/boringssl at 2019-12-27T16:10:16",
      "privatePkcs8KeyData":
          "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDZepV3nOVheSUpjNXV5fZ0iWxV62ziYWj3qoLnqrCU1J30peDYZvSJxTT+3P576w7Aw7r/N8VWZcjNh/12RS08BAljGwndG1lBUTtF6HGnEaQsTWHzAPV+cghlTcoyhc0KObdn57VSUK1h5RFGN9rjFGqRbBEL1aBN6L+ydEd52zB226k69xpKIvBNaWUNuRM0Jv3kXHTVi6y5eVGXJgy1bz0zgONXk1yCxZndCE8+Q8V91uX2IeREubn4roOYJacT0zLWO1tbuHhTs4Ib9tBRJFZRBb/z4j8X458BzRAtOL6gLyslzJ5fyFSSfgp9YVoVti7EBnCwKtVdE12lZCT1AgMBAAECggEAIyxr0yopgS/OPl+cUBl+2E9HmcfXVu/JQdEuldhp8dBHccOIT4erQkMGdLf6YsFcI/okGtYC0RvqM6+sYz4B+GRwvjonyL59G47PRtm20/4K7u1fC6XajqZTzEqeCrjQNjiqfKAhl9wbhqs9NX2gJbzuFXIEecUFxcQAiRS8YK0x1rKvPaz3UKB9s6YIzn7Mhj1arGV5Rsnl+oqwt5o3nPJTl7EuzqKZVMSgQ8hq2viuwXq+rLJ1XuPM2qPbHU4gIqx8elB07KN/hiCEGWBobvMrxKUY3gVjMCSehrP4Sn6gHPY/W5swyJmIa2JUocwEEhXiIqHwZyPi2JhiG7Ll+wKBgQDzsKjFl0ZcOqhA+2jA/Vf+XaFtW3MTl4y4H6EPITYXg2jqA27OvW4o1LYi+M/6GJLBYgT4+ffltlwBEj3C5vv0pX4Ba8pkYFsQT1j+JNmNL6vRagKyrXCBfotlo1qIGaxByp0ue6Cfafil0Vl6bnMISQtcskHr+ZdqwaDYRNJyRwKBgQDkdveiMM5XTZ165RU+YgwEbPrlwu73hazR4j+l/xYmLAAOeYKtcN8mSnI4s7r3xyjH3pUYULSHcRPb+4UnsmBzgfD7fS9TYq1hy3l1/vOUkBvkAXMa6xIhKkxJ9CFIue87FxYODsnL1dadIzTREpk19jXABwSnRdz40KxJsgiw4wKBgQDHICPI0cP8uTGjZ8xBZsLwZzHxWji+WafzDGVfJ5Q7wnWIQyXYaZIKa0YpbYcEpe/FdYL6r8eRPWIQvgcZrAVV86TzJFFNlC7VNQFTKmlapQmRJT7vIio8plrhwonHjLLlT9sAkKS/nqg/VsH2+SmmK4nNRRv45wqDgZUdI5+TIQKBgQDfcd92WKemyTlpdd4WGkzIk1G8H7AalDnXOKGpl1exU71mar89JLSLPaqC/H2zUqz29iH6GwzFnvmeYFv13EbrEb6AKQp9Unhiul/74LOYrG0qzaQnQpuDplvgxI09FOT+dPDUJPCGlIkHPOSuSrNgDIK7YeHSO8kH7QdkOGS5owKBgQDO3c7z1vMfW5be3an2MNTS1g9c6NEpoiq33VLGrCNr/j2F13s/X6l7NFyaUmNeZLZiNvEBXzRScf4off3WuqThEt+DCJ4lKOnOsjR51s3cMr1rK6AvB3wA3luxy13p7LI0b06+/h5pJ9D2OiQT7gjh3VCqS9yk1iN8TqWtDaxMqw==",
      "publicSpkiKeyData":
          "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2XqVd5zlYXklKYzV1eX2dIlsVets4mFo96qC56qwlNSd9KXg2Gb0icU0/tz+e+sOwMO6/zfFVmXIzYf9dkUtPAQJYxsJ3RtZQVE7RehxpxGkLE1h8wD1fnIIZU3KMoXNCjm3Z+e1UlCtYeURRjfa4xRqkWwRC9WgTei/snRHedswdtupOvcaSiLwTWllDbkTNCb95Fx01YusuXlRlyYMtW89M4DjV5NcgsWZ3QhPPkPFfdbl9iHkRLm5+K6DmCWnE9My1jtbW7h4U7OCG/bQUSRWUQW/8+I/F+OfAc0QLTi+oC8rJcyeX8hUkn4KfWFaFbYuxAZwsCrVXRNdpWQk9QIDAQAB",
      "plaintext":
          "aXNxdWUgY29uc2VjdGV0dXIgaWFjdWxpcy4gQWxpcXVhbSBhdCB1cm5hCmdyYXZpZGEs",
      "signature":
          "G42B0CPZKjTDZgwM/9/JBc4De4gPNf1XZYpRAh5cZXPoQ66hqFEEfkR2YZy79KpNNxJf+didObXT3sz1Z16JHa4wBfrVDuhHWbgDpXsmb4H1GiXLC7dnwhxacEYMV8wlzykS387CpnLJjMAjJ2Tef1i/kIHLyRM7Iz1VtzsdWvFxN5jx6pqxGHFGtg7PDOfnQxU/GO7+9qCSib6WJMrrH46rs6Y3s5nP0IDRgjdewuausru/gdfcOV4tNC0rdbaCW98xFcJZ9Ouv7ki351bQ6f3frYH/EPHL2kZLz38KzbdXwjLFthzonrNN05O16vPd6AEUSbAKsld+dFbHslwTMQ==",
      "importKeyParams": {"hash": "sha-256"},
      "signVerifyParams": {"saltLength": 128}
    },
    {
      "name": "generated on chrome/linux at 2019-12-27T16:10:59",
      "privatePkcs8KeyData":
          "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCt6SD1xIygY6EBDc6F52jpMVePY8nWUDTfS0mLUdbruD102z1Kke+0WobPayLZ4ySnFjnUB08SYrx6joPY4AKSf+aGVuYSjo/q/lMd4YaDBPOXypSgomgPVpbtrvtC2YNeJ9/ziW8jIBUKGbdJmuLueN4vA9SVpujn6CDoi5wPXL7tPtfMVoBVLmLKHgj2skCVNouo7kzMwcb0YYSV8gSetGNDR3jUxVircuac4tk4v7QsT7FbfUyTM/bWR9qWylr+7ofbHTOwoQh0ggJpOdB4QuECMcunCY9UDC8KdUadt4ItGuT1j6dEzUz79bSvn0vdjSkjSlENfxYaxLU6YhsDAgMBAAECggEAJyVy5d94SCIk+7e/5SRR2SviKcSsijFDtX+c7l9doXG3Y7Z19XMkIdS+w7G6BpG6jmHSYofCpMDU7EFoLElASvm/Sj4FS+gLPTpCO1eoj5Vtv506F253PfyfvKDGriWIDImtP4SQH7f5BG0FdOwIaOWMHcke8RDBHHKD9dR3LH20xStWAQczS0YNO2QGaHWkx8m9Yx6RdqKsMz+iPiAJ7mT1yssdEzew4Q1Qyero19qfZdFr9I2GKkVq2masrbuEQ4HskTJT6e5qNjq93r4KLq3nR9JME3UmzeFI2FaYox6Qzc6HeQK4SxPksEO9F5BY+TFsRSxllXGjxvto+hTyAQKBgQDiBFRephWWLEL9shqcLe7kzZjptqP8Rf9Laf1jbZoUpZ28USr7jRpeQac7x9AE1V6CtnlEss+lWzvhqY2uYX0fjI2HVQg0m2t8uA7FdVuwloMdtnHtjGyV5UKDTWz67zzEuNE64+OaFSR5OJTopF5yEehI9khM0UG3rW7/meyeSQKBgQDE+z1Mgnv7DdMXUyHvny7cGhsLO6l4ske1d9xCg+5Jrvkl1uKZoUS6rZNFXKUba6Y0Oq6wTbhLu+7UwunOj6z9RLxZmPtc/vTHoSdd1EklNtl7SIdvfxqTM8i4nw4cCJfTc753Z5GmxNPePfTVkNnUodCmlhbui81QHfBdg55e6wKBgGndT0t6DbhmiQZdqxsmZLRlHM+zzcG3Y6oGPjqZNsee/3AasMBcylIF/HgC0ovBCWC+abTk8F/qiPTdP1DDtyDU6+HM0WgauFEVwU159/WRul5re5eh46aeWPY5iOdMsbEPRGmKHqyoZIonF5CUlOxnON8cBKd+iIKpSMmOZoeJAoGAJMYutHjrwnvbO9CGVmDmc6rf/6Hcyq6l2ogM89IDi3gCBYFvfnTwCtXa16krHcpkFf4anMl1rZXhSZE16x1Bk2rgqu13h+4FLru0SL0YBr2Nrolk13joMjEJuQXgsXUdOxmxpkMMmxDF6QiyC6jmMd8fv+nnUBODegCM3jhzOY8CgYEAonJ1c91X6JC45BTxUYQ02x2Z0lp4+6aJX/BowYk4/alVLtfYFTACCRtiafCvIwH9nK+itc+iR6JepUc6YUONkK+zg7RMecKvBMo9hBqOVJTE99u6wMm9ch1mL9vz8Mr5EBgdx6kkiXFzwI6rGBvSUfoP+jaO/no8MjZEf0/pkbw=",
      "publicSpkiKeyData":
          "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArekg9cSMoGOhAQ3Ohedo6TFXj2PJ1lA030tJi1HW67g9dNs9SpHvtFqGz2si2eMkpxY51AdPEmK8eo6D2OACkn/mhlbmEo6P6v5THeGGgwTzl8qUoKJoD1aW7a77QtmDXiff84lvIyAVChm3SZri7njeLwPUlabo5+gg6IucD1y+7T7XzFaAVS5iyh4I9rJAlTaLqO5MzMHG9GGElfIEnrRjQ0d41MVYq3LmnOLZOL+0LE+xW31MkzP21kfalspa/u6H2x0zsKEIdIICaTnQeELhAjHLpwmPVAwvCnVGnbeCLRrk9Y+nRM1M+/W0r59L3Y0pI0pRDX8WGsS1OmIbAwIDAQAB",
      "plaintext": "cyBsaWJlcm8uIEluIGhhYyBoYWJpdGFzc2UgcGw=",
      "signature":
          "alb33bpzqY5CYzDsoX8if9/AJvixYkWZ8IgiI/EweQQHfRacN6uRJyWHiFp6gsIu2lutTWZtQylhmLB0869hEjJjhAOYlo/H4F1LloDGIG+wMdvd2Qzhvhfkq/28bVkrPfnUinza9cr7JxzbqyYbECHBLW/ZHOsf+3igueG+bFhH9DzzkPyo+rnV9K5niiDk/XP67oM420DZTGt1GQFSfnQoMo2nf1H2m93VU/T0plm5KmC44m3C3yzTTm67s/xSCkWJZCvu0XS45kd8roUubML5+3OdC9QThg68oVMNgIFpVK2/ZOg2mJ19ZiP8NZB/YoxTkp9KoqVsp4maNCqIvA==",
      "importKeyParams": {"hash": "sha-256"},
      "signVerifyParams": {"saltLength": 128}
    },
    {
      "name": "generated on firefox/linux at 2019-12-27T16:11:21",
      "privatePkcs8KeyData":
          "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCn9fTqNgFuHswAnL0B1aC/ayNxVmkxXj9YWT+LHStjJSLFpSH4UmOXO+Nr4+DvGHkJFXBNw+5teoLvlqHEdEO2bv+WfwKEqfPsKFhQyaqQNYxwUn24SqSkcvusZ8x8UfNcvgntHd2cCYqGgfovoYFv5VmUGMMdi7cHcbN6fCZgdV3u3wrIfjP2FV2mStAv5vKxRisdAR8thWPX37F/D6JNQ+cTMCRPYFS1WSkq87kufXcNSRyn4m4cGBSwW2wcsFsWBXzCH1sEmTOKekH7TacnqyD6J6bBapqIxePPi2sDz9tfrm7xOdk68LChkhOKyj/rwPOD/R+Ubud52nEHAZpDAgMBAAECggEACZaNPQy8MPcdGjClMYRqdFyMKp1a//B4MtwiOBgAMN0fCqPBa3v4jdrJwfaORQsWmoglkxFLFec9r91F4TS2sNfOGCwQwe+Zw+XbTmSH+H3pRUUDdd1jX+flQ60UchX58iKYtBDvMUfyJ0XzbEioXotIyji0dFLt4RG1w//WVc2fSVRsUqbugPO06j3X8qNeEpUyrKDRxbagyPZQdTkEIg+70So9pi5GTnBlATJhOGS4oTjHdgcYP/E3BjAqy7gdqg9cC/8VXGqI0lrgH8GSW+7uHNFWCFGNUI9mQ+Zq9Fc/LmxHGgcLqBUAO0Ijm+YLMux4PqTH1cIwVDoZfDqKkQKBgQDcRcyOw9mherArkvDnaVbfD0JeYU3IMBoDocv8ZsEBAxQjPLFxwxGpqTV/SoXbboA4TVBJHNUSP3lQlPDtBV0DVTAx8GiAS8rfOQGStN41mY3rKKAvaLFpwRREyrszVLm0HqeBlXw+Vp4oBq6xEAt87Nt+NsghfZoJ9s2fquSYTQKBgQDDNA3a6+xXenNF+k9Gwv8nZedNf2/l2165Rty7SPsxYOneN3dObIHtiYg8Jbg7VTgozWWUNNm+5p6sK8jN0U2cFhsGp61mkRIR2wfpQhqrA11rUYadQGRIo8oBxCTYN5JJImiee18Pai0Dl5QPKO4QzLiEcZFIJTMY59rpuY5EzwKBgQCZF5X1f59JgQjiMA1o+Kic/XEGQaCayvu5nIE22n+34VjkqLE3PPmQrn71CmmAOgu5ldqABh78wMrjO7E7OugLgfCuNMWcrZDBllBGk5iBLkkZsLGsYZo0wzIAIdr78R3kVw3anXetp+viK8rMWzdwyvo+fXqY9D/UPwlouJCKXQKBgBmXaXmaFJIja5lxB5OvXOQ9Z+WxH2pzKCgCMk4bc1M18XNAslOFxkLuFP5Ns6mTspkm1Hpps2Jjucm4s8rH9fTQsRpeQU2BF21f2dmq4PQqrMS1G4DiQEOFtaYloO732iXcbPraEcxjjyM5bB/QreVl8YrrmLBssBZDz191BEHhAoGAOlOTemgjx1uvSoXGzmVZB+nWYuGHlVYOiOZpObCORX1lDrWiedCjIewBTX3TDHf5pXWQyfYbdCyUfoyEx2Z7K48QS4aDhOLfGEfQHkJLkWWtPv1gIu5pmySHoehjPdplszngZ6sbjoNhMcaPcSvfamf1xiQ5h/eQZejr5R4flDM=",
      "publicSpkiKeyData":
          "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp/X06jYBbh7MAJy9AdWgv2sjcVZpMV4/WFk/ix0rYyUixaUh+FJjlzvja+Pg7xh5CRVwTcPubXqC75ahxHRDtm7/ln8ChKnz7ChYUMmqkDWMcFJ9uEqkpHL7rGfMfFHzXL4J7R3dnAmKhoH6L6GBb+VZlBjDHYu3B3GzenwmYHVd7t8KyH4z9hVdpkrQL+bysUYrHQEfLYVj19+xfw+iTUPnEzAkT2BUtVkpKvO5Ln13DUkcp+JuHBgUsFtsHLBbFgV8wh9bBJkzinpB+02nJ6sg+iemwWqaiMXjz4trA8/bX65u8TnZOvCwoZITiso/68Dzg/0flG7nedpxBwGaQwIDAQAB",
      "plaintext":
          "dXRhdGUgdXQgcmlzdXMgbm9uLApsdWN0dXMgdWx0cmljZXMgdXJuYS4gUXU=",
      "signature":
          "YmhNMxJbCaDp/Xbin4HtW8mQhJ3OaVofpX9RxP3R5FOrT+ehGyuNa0Qws02Ko2FEm42FN+KNh8mYv1fzFL9izXHalrti03cUVt5k06qaP04xIxInVQ7w/9kj6jQ5zT8O0TbzL76vm+ZRutsrrGclLrDzhXcgjpThCowAFnycUd49kBDy2iM4lCXa/bCiaD3TsWxvIxhCTyeNuZV9DtIVa9uGwfoeAx3Jj04KRSN5A/ORfsSOfHbDHGk8ANuMSyXvQufxRjmC2EQxXqy1IjUnsRbDVbCJbjDDhyUHUlcP1aeqjH2b2iiOqvamychpHLxekA5AFY1GyfsrkMK98+0ePg==",
      "importKeyParams": {"hash": "sha-256"},
      "signVerifyParams": {"saltLength": 128}
    },
  ]);
}
