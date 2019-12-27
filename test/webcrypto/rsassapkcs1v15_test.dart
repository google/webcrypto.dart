import 'package:webcrypto/webcrypto.dart';
import '../utils.dart';
import '../testrunner.dart';
import 'package:test/test.dart';

final runner =
    AsymmetricTestRunner<RsassaPkcs1V15PrivateKey, RsassaPkcs1V15PublicKey>(
  importPrivateRawKey: null, // not supported
  exportPrivateRawKey: null,
  importPrivatePkcs8Key: (keyData, keyImportParams) =>
      RsassaPkcs1V15PrivateKey.importPkcs8Key(
          keyData, hashFromJson(keyImportParams)),
  exportPrivatePkcs8Key: (key) => key.exportPkcs8Key(),
  // Not implemented (in FFI) yet
  // importPrivateJsonWebKey: (jsonWebKeyData, keyImportParams) =>
  //     RsassaPkcs1V15PrivateKey.importJsonWebKey(
  //         jsonWebKeyData, hashFromJson(keyImportParams)),
  // exportPrivateJsonWebKey: (key) => key.exportJsonWebKey(),
  importPublicRawKey: null, // not supported
  exportPublicRawKey: null,
  importPublicSpkiKey: (keyData, keyImportParams) =>
      RsassaPkcs1V15PublicKey.importSpkiKey(
          keyData, hashFromJson(keyImportParams)),
  exportPublicSpkiKey: (key) => key.exportSpkiKey(),
  // Not implemented (in FFI) yet
  // importPublicJsonWebKey: (jsonWebKeyData, keyImportParams) =>
  //     RsassaPkcs1V15PublicKey.importJsonWebKey(
  //         jsonWebKeyData, hashFromJson(keyImportParams)),
  // exportPublicJsonWebKey: (key) => key.exportJsonWebKey(),
  generateKeyPair: (generateKeyPairParams) =>
      RsassaPkcs1V15PrivateKey.generateKey(
    generateKeyPairParams['modulusLength'],
    BigInt.parse(generateKeyPairParams['publicExponent']),
    hashFromJson(generateKeyPairParams),
  ),
  signBytes: (key, data, signParams) => key.signBytes(data),
  signStream: (key, data, signParams) => key.signStream(data),
  verifyBytes: (key, signature, data, verifyParams) =>
      key.verifyBytes(signature, data),
  verifyStream: (key, signature, data, verifyParams) =>
      key.verifyStream(signature, data),
);

void main() {
  test('generate RSASSA-PKCS1-v1_5 test case', () async {
    await runner.generate(
      generateKeyParams: {
        'hash': hashToJson(Hash.sha256),
        'modulusLength': 2048,
        'publicExponent': '65537',
      },
      importKeyParams: {'hash': hashToJson(Hash.sha256)},
      signVerifyParams: {},
      maxPlaintext: 80,
    );
  });

  runner.runAll([
    {
      "name": "generate a key-pair",
      "generateKeyParams": {
        "hash": "sha-256",
        "modulusLength": 2048,
        "publicExponent": "65537"
      },
      "plaintext": "cXVpcwptaSBldCBvcmNpIGltcGVyZGk=",
      "importKeyParams": {"hash": "sha-256"},
      "signVerifyParams": {}
    },
    {
      "name": "generated on ffi/boringssl at 2019-12-27T11:58:26",
      "privatePkcs8KeyData":
          "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC0L60Nqv473kYJU3s2cvd1x0Q1x2dzQS2Wws5DToeZglP5hv/SKU3cqHXU7BulaXQ87EgVej/AWmF2SqsauS6ay8xyFF2k3l/8+HQ5CMVdNjRkJZipc+1oOSc2kbl7nkf9pZTWefmBIgjzqkAlDfi24zm/raJiImn/4WgDyk8vnmDkkpCMNNnDDqMcPuMUylDWSmz0E4okkiOHWabJUgqaaL47U6wousuGZRrcQ2JW38rgPI+/yld8OnBus2Q0VzsaC082hs9UrdZnFbT6M1wH0y+bGNDzcoj9ZMMk257I/TzY+CXkhHIFMRGUTGfWU2YsKBWiA7K+yCb8wPUoAadRAgMBAAECggEAIoiaqapyhGXi1Wm/DR32qIeS3p3DiXbd9m2Km6LC4Vx1nLbPc+d/qUFOKAtCdy7hXMXKQPeHnWWVFVdVOM9yC6/wlJKrqewGyJSTrdStAuLfIqyD+EIkJ5wAlHhUbMlWsdnYz0xcUfAEeDLSjWeCmgatrDtqilVfLG/2f/d3ur/VKZ3DcviKNu2msJlk7ZXVymRVJbdbOGzHdOcK7MdVCAk+EpSLuPUJHkJ+ErCEMhIwH+3TX3A02CPHuZZ/N05Yx0AWDnHuxgkrqC1wqi09mD9eJJnDsOHT5qwTGSUKw4ozDebJ5nJxdBTBk+URguN1aqitC7NLYrsHYnTDr8BHkwKBgQDbBveDD1lzIUPJ6bdnsuYZUcXc6PjqsNs+CL/U5PqJ8J5kJOpCvoDspUngi3zQWtLw2J+yPPW8YC9WwPv4ZFlD6NsztEYFNFWJSjaz6m0x+U+ADi+JOoScWfxvsO8ofvlqmPMY7H98YJs2PxpmfZm4Rge4wObwmSI4zN6jwnYwbwKBgQDSmjyS1pDXlguWXzvoR8cQWancGGxSo57uLviOUjuauTaqmPZNSeLCWX8r0hfx9WXnbZeE6wnq8kokgPb2yWhYJ4pEsE4S4NPb+AJrgtQpJmRUzZfm05FD1Go8f7tYST2+QQBQ57+AfYpmMrUEva9ZlDEFOL7HOLTbf2Ycb3YEPwKBgEjTjTLvxJ9KXT7izk/VpTqf/PlSIYnvmkaLJDXGmSOKdS/5MkdVDosg/mqCFtM0j9TzQk5ChLbJCJSBAIb73s58u336oBmU6CgJHB1AgmROcEe078tiQLu4E/6TR0Igzg/KoXIVGOKjQJiN7NpNQvKJnoGo6mDvmfhm7lRnEWNTAoGAdPR4jSchOsg12SU8FKu/zcGthe/+QApjmWx2VjsupKcUx7q4lYVhq4KeEAzVhWY9WD9RNNx+Hn69U/ZWsAh7rPEQZULvqKY4oWDinygBgHS0pS+jmumFM4EEGmLo/Id4BW79qPB6NfYB5O1l/6MDfSDB9F9l+ybvsTHX2BTCGmsCgYEAhq9OzTYMHicu4yq+X7WvBvebneV1WDYvM1/ExdIZL9v09VS0mZKWpej5hRSN78aoX3dUo7wAx9o0/LpVvkvihgQgYohsmdenJCHj+lpCPkmM8ygRDxFZ0YyeTwKEOeGyceBlYiq08cQ8E11y93aMj3vOM5K881rSYpFnMCWS+HE=",
      "publicSpkiKeyData":
          "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtC+tDar+O95GCVN7NnL3dcdENcdnc0EtlsLOQ06HmYJT+Yb/0ilN3Kh11OwbpWl0POxIFXo/wFphdkqrGrkumsvMchRdpN5f/Ph0OQjFXTY0ZCWYqXPtaDknNpG5e55H/aWU1nn5gSII86pAJQ34tuM5v62iYiJp/+FoA8pPL55g5JKQjDTZww6jHD7jFMpQ1kps9BOKJJIjh1mmyVIKmmi+O1OsKLrLhmUa3ENiVt/K4DyPv8pXfDpwbrNkNFc7GgtPNobPVK3WZxW0+jNcB9MvmxjQ83KI/WTDJNueyP082Pgl5IRyBTERlExn1lNmLCgVogOyvsgm/MD1KAGnUQIDAQAB",
      "plaintext": "c2NlbGVyaXNxdWU=",
      "signature":
          "ddFjHdBe2CppCRVfNDyMXaPB166jMHd1IQHa0UTVwj5tVAlRjFT+wgFjEXignhEK0IwxfCmDoCZsYpN2L4cCoKBZK6cspUll/aDRp/+defeASaLt9rLeAp0OxlZ3MNigU1U8rq2CboSSQ2EEFvvWiZ2O7Jb5Vk4tJaFhi2XzejXt3sZ0Ss3rcNnoL01IX6R6ISz+x1LbqdMSh4PQJ4M9RVfAV4x3MnFkBHJ3v3xxWl5ecNhRX4J3gluC3IAv14VoNSx9Eb9KJhC9jxh+bWM6jmyV1XVEAYteSN8WzUNUh9pX3Re6Ng0lEBU35+vftUv1v/GZzF5D+umui+ke0RibEg==",
      "importKeyParams": {"hash": "sha-256"},
      "signVerifyParams": {}
    },
    {
      "name": "generated on chrome/linux at 2019-12-27T11:59:07",
      "privatePkcs8KeyData":
          "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCKmaLi6Dr/1XbH0bbfImDmW3mwBIr47ObbZbZo0kj+Wcrc/EY3T9P9UJYlcyCNAVD+s67qzzJA8eer4TQJbIRC3TiMm1f//GkFq1Omz7KuOgHOnQX4/vqQhaMOB9jDyZCR/x6rrKA4Mv5zXGnjh0rRAx2kQ7td1I7+TYVD+wwsXVYAOghkSgZi/FON9R5/4kEfBkwgi21u/YC1pyQWcSyQj6t0Mod9kAan2/rF559nOZYUUmiZIMqMhi2/bg31eNYl4g+GwYeyLSz1jyiNVHh2rivx7yTP+U8RamT1ytGX7w0HpoJ51C8hyNjDrcdcydL3fhrauhqDgVXXFAr3DP3fAgMBAAECggEAEIETAGoe/G/y4QB8Aj4Zw9SIvQkNc27iXqXR/tFrl74hhgcUZWnAGJ4MAxGegqvxdSL4ZUWe+lTT/YenpqehaETngvbMl9L6vo4UO/znjg+iP3Q7TdcvBx6it/z/NvE9oeT7Rf4cZhTMb/hFM67cnd79HJ5kJVw2WtnoUJwIaw/VWgpd3qlD07MiTBC7+/d8IpCFlbUD8FxTNYpkGMuqXP0gV+DFfIKMQhpb2f0JMqL2PGmk5vJQZOMU813WftbFumJuf/t9AUcJBcehyw2YcYT5XSPFO4BsHB0W0lXYGW51+Yzs7QSJU05EC0oFMVqLzs4FHlnlIZazcf36wsjRwQKBgQDA/0c+JHGm9qyITAinYT3/a/10lonkopb9HHPw01w/j61jmCztsD2LKDADe7j9+G9YBFbv4t0OrLTMNMyTCx6NudKBDTB0u7jcoGa+yX8Fenr2ReQG1dBdN4mUOzgUzSKzDuKSvmWZN/eczpt0Z3SE1I6L0e6lU5+zv6dTIW0b2QKBgQC32GmK1sVD1hrZUuHV1XDyxaU+u2N/b+KoRwHPTZYzLpA6T7d7tjout3u+/LyAHW5+o/8aN8yczXcLg/qDjaxnnP+migjXPCDJJ5rYr0DMokV8Mj0pz3X7BL7/MpzkcVtlH+dIgDTGNJ+Gb7CNocILTch1kQctbfOTX2ozSFHsdwKBgQCpy22oVHPRCtB8ETjD2Z+r6hxQyGiEyC7CfJfcVnegTA2lw6oza4yZsz+asOzuM/Xxn8/EuPj3AicGSaV58Jxu3/89Hpd0+/sFz/DVBX1FGp63sIGPKelpOYVG7lrGojtXAU+A/xVvmXe1c2f9H0+51S+b/5RPy6SDhaf2UUAm8QKBgQCZBkNjUz1DJ7WVaw2bRVwMV0MiIivBaUnKM8Bn4vbAh2N5hdz91kI7nHIeGJR2Nwk/1BWEpyli4wrRxPsCASyd2epZns+ZB+1qQdL7xXQ0YGVh6RdL8+kKFXs9Q82fwFMIqzOB/2TuDeMyrUjRuvCfJBFU+nB0+e4inurw4KOAJQKBgQCsW+rs1XH9GG6dtdrZs/+oqbxTtI5BvqoFDK70qdEbqyS1KCHS07qJLyhWhswTNbS4Q6TqNrLuO4LGyoNCKrMT8gQ2krfK4RpTPxEOlOz5ML+syYgDqWrw/orfAdczX3FN7sD79hsjKm2AECPTiysGMl5iiArU0nJCJK4YRBZrkQ==",
      "publicSpkiKeyData":
          "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAipmi4ug6/9V2x9G23yJg5lt5sASK+Ozm22W2aNJI/lnK3PxGN0/T/VCWJXMgjQFQ/rOu6s8yQPHnq+E0CWyEQt04jJtX//xpBatTps+yrjoBzp0F+P76kIWjDgfYw8mQkf8eq6ygODL+c1xp44dK0QMdpEO7XdSO/k2FQ/sMLF1WADoIZEoGYvxTjfUef+JBHwZMIIttbv2AtackFnEskI+rdDKHfZAGp9v6xeefZzmWFFJomSDKjIYtv24N9XjWJeIPhsGHsi0s9Y8ojVR4dq4r8e8kz/lPEWpk9crRl+8NB6aCedQvIcjYw63HXMnS934a2roag4FV1xQK9wz93wIDAQAB",
      "plaintext":
          "dWxpcyBtYWxlc3VhZGEKbWF4aW11cy4gVmVzdGlidWx1bSBhbnRlIGlwc3VtIHByaW1pcyBpbiBmYXVjaWJ1cyBv",
      "signature":
          "KcKpaM/maekwPVlz0jxqbSPHN46kn69llITMLCe4DIUJmawJxfn9Tiy9EWL+dQlfVHW375Oq8wrYT+4MjPqPzr8BgOqdHn8wq86zkI4KmBc1ed7dbxkp2o0sn6JS2jhLWVUOvo09ga+hCiRx2nkXgYEVtH4ehyJ1CfhRA32I7bKrmU37WBRJygKQGT85AubDdFVK69yUHeQjOgEmc09TFtZIKpMmMC3uiDo5a9EJ9g1khD0AD8iTI0XVLpYPeRW22quISucxpPWXzVtqGaxBQKP70O1UPXSKYj9PkrHoNrKampHAZXGJ9MZtj8Akcrj0MhvoTbuih7SuM9MksK2s7w==",
      "importKeyParams": {"hash": "sha-256"},
      "signVerifyParams": {}
    },
    {
      "name": "generated on firefox/linux at 2019-12-27T11:59:30",
      "privatePkcs8KeyData":
          "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCuCWKLEvxwmhKREtLp/Am1VxvV+dulCebbWWySD0+NJVnvjWzKD5DANZtMp4PSX/nRwHo6jHxYS2ILvbvZfJ0AP+eF+xCO1gJwgNgwh7VTiPiv73FMskArhThJSiJrq7iSY4vy/pRLi8IJZ3QLWpozoKfbmowyW/p06uVu4ESCtETcahRiBePTI90el7UR84QsezngWpEjvQKbPjTf92wCDX+2z6KQhb8DmMrcA7nMik7pxwgUATa3XigF5FHqNECYlFY6kT1tpp5w/SQGpa+vQycwdR7X5XLQq2vLhulATmKObO1vTGgYYiuhf4rRimhb3H/Y6odBZ+EecLxwI1aJAgMBAAECggEASiQ+YnAeshu5ICusRbk1K5dmCOTOQUN0IWs5uQmjwsYwR8DwoS47ZN8Rf3j3zBZOF6EPkUTLLlRC+yyDy/Xt7q7Kw8W++pLKbEI/l4Eg6ur1wwHXOyzO8Jtq7LIT8tmvolGdS9JPu9VYvuffRHz/J1JgYEo5QrTzgH6XaoJJPYK54P7184d2Ty4IlXj6ns9h5ew0OcZ6Nbvg7E0KTNX+3KAjoWfm+IK17MpfgcakxnaCasgf64Ue84FM2ryuuM6VMJ+0Smh9FlrwO8/fzNI5dURQOEKWVa/zlVwvb4lM9RyRBUYjLNwSSbyfuwLwMW5HZCHzYMGpugUxHPt5v6JRHwKBgQDTNUNUhzi3fgiKpSWzOWxeAN2tS6W0dwhlf1d0cuy7gu6ZrRMbQHd7TprendptATKP9K3+/5mzsRB5u3xUVum4RFpedOxs6w1HJPwZFRMW06uHmvK9SJ7SCdHuIiatMvurVLCGsy0dzWF4za0RME0HRgpa0NNibz7Wvr346dKMSwKBgQDS8grcmtjRzttn3I4KjvodjZeY0m1ep9FIz2TMy936gA5Sp/usa91Cm0+Nu/wLefVwcqkjFjzhOl+FVNcnZ8ohpBrk58TiRblsXGJG1c7aygRY9kdGgzYOiLY/CwHxZtLZicgiP/8KbAWauGZrKE134Ercpdw1dh2pCVB0MQu7+wKBgQDRA2zWQdtG+1rImhZs/u7XOFQoIyyhIwsUJqkNfI36IuCtBDJcTbfwNyHcHKsEJKM9Aw8NwzUANsHvNjMb48b3q+0ifONcBmDlfxxcVhbGCEM/t39xAmTpxv4Rg4py7HlSXEU1iCulypIjUqdq0znncNDefroyN5UgPzMRGZRbcQKBgEGlV2H9wlnQoRD6Xy3D/uwxgyro2WZqnUOmXv0ouITbUxm/8x9eVfYDdUdrZ+1+X7ZFyIMFyZ5h1xYcJ/S4ZPwBIOl5gxjTj/e77E2U/hGyapXw1o+IB8uQGf8Wgt1IHXfbW+/ksI7ivP/AQQc5/JnAsCtoZlYw0twm7OWr2bX/AoGBAIUO0ryXulQJhTb4RiE9bFf6+zf9OhNThKN6ia87IuX+CSJclv1QKzUPYoFO8l92Cu0kOUkJYGlJXTm9NTd7kEa3Xu6Ax+3UKIA/d7yanptyrAep7h1cPgR8bdRljTNBV0JUJE62yHMYi6DPV8cSi3cKLzLf5NHKKqg3jL3eVtp5",
      "publicSpkiKeyData":
          "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArgliixL8cJoSkRLS6fwJtVcb1fnbpQnm21lskg9PjSVZ741syg+QwDWbTKeD0l/50cB6Oox8WEtiC7272XydAD/nhfsQjtYCcIDYMIe1U4j4r+9xTLJAK4U4SUoia6u4kmOL8v6US4vCCWd0C1qaM6Cn25qMMlv6dOrlbuBEgrRE3GoUYgXj0yPdHpe1EfOELHs54FqRI70Cmz403/dsAg1/ts+ikIW/A5jK3AO5zIpO6ccIFAE2t14oBeRR6jRAmJRWOpE9baaecP0kBqWvr0MnMHUe1+Vy0Ktry4bpQE5ijmztb0xoGGIroX+K0YpoW9x/2OqHQWfhHnC8cCNWiQIDAQAB",
      "plaintext": "IG9yY2kgbHVjdHVzIGV0IHVsdHJpY2VzCnBvc3VlcmUgY3ViaWw=",
      "signature":
          "fr8U+vpqgyv4/fFx5y98j/24TKmZSSljOshCBcvHQQIt1GUSUyYxnCIUtbD4KOhZbGC0KO12zEv2Ym91plxlO7vazr4Ypv6k4NbWrgtdImAkHOrIkjoncxtdQ0mYnCOTKjo8ZZS4cahT4fKbZ2WErHvuVZ1wNJ8Hi9pAtEWc+l0CkqzpyIMq25XieT5KUnoBfejw8iW+hUElPX7Cncve+2ZwrS5elAaDgoUpgRLrm0713AMEeAi5Pd+BCGPSZ6nt6d6QwU1wnbRiZHYQk6PvAGEUjJhTOBcwCc2kWmyB/ZMN9Wrmu1WxNeeHTkQ20/X0+gvx5/3/xrrCigVtyVIEjg==",
      "importKeyParams": {"hash": "sha-256"},
      "signVerifyParams": {}
    },
    {
      "name":
          "4096 w. sha-384 generated on ffi/boringssl at 2019-12-27T15:27:33",
      "privatePkcs8KeyData":
          "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",
      "publicSpkiKeyData":
          "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAunHYH/ZB44eZzNjryGYykF1I7M5x17DQfojPwgZnz5W4Je7rOv1K88p5IayrolOPZ3onYXAnVR5VIV60NEnwGka/P6gyguOrdrPZ5iCQTCyTk1ulNb7BzQfYi2UFKAEBoCL+gkUqsVnNv76LmAPegn3YFwtKI1WH+O8VZ6Q2cBwDdhMuIklHNSR4VJyBEgYbIe6+kwKJbI1w6FTkVZx8zl9jmDMaAQvjcR7UzroqakfFV6csSCSzFExTfBR275QYjPScv3biUp8H3iqcX3wkdo2LbFmWhIEsa5a0VBvL5SMK/pTRVVrgVc3eDUbzcJ8vIUKSopygRpMfRT2Po0t257JCpmKA7h/aKdxxqk4Jwr9fdHSutiKzTXojmEJoQInVxZwEZCjHd7//bPBhNRDvfCFL0BPK/AWAj54Ml9UKWfZz5K/jg57C/RienhMGWIql2ZxQcgS1UImW0dLIJFsP9Mb93Fb5KnxNIGJ+cENYvotdqGw5m7I2Dv/ML3KsZ0qLcTtvut/EG4oAn+YmY6N5TDk9hrr/bXW9U46w7SNTAw7MUk3XZXQfHiyCmMqe3yIwei/XcXOPORHok0zWKXv4kXtZnAF1cESn10RA/8Mvj4NM14JCL9n+Yvvv+3lJ65j1zfJA//QAxs/5qtLkYCLA0c3xZbcz5gn499AamXPO+SUCAwEAAQ==",
      "plaintext":
          "Z25pc3NpbS4gUGVsbGVudGVzcXVlIHRyaXN0aXF1ZSwgbmlzbCBzZWQgbA==",
      "signature":
          "d+nE5LkGU2CB4+3waj5ssN+3rMTiXVrde8H6EWlIngG0RDcyFvSzkAjyrWLck2+FMLiZJH8XXLy4J2RNAJ9syhZsPUjD+zuTWqERgLUpmtzi1xn2HG+pdo/rai625PwzmnD3//C7T9ZhGthrMJyDmqPNqPj5UPD+FerzW6E4vUj3CJHWBxd+60fLOYAqXX4Ig7DkmKYoPSFqSTHk/rNxiRk8gAlm/vmIt0KFo+cLH5J/Lx7AtZ6j0NiolfOZH7u9dN9CgoumPlSrhwpNX9GNr5ZF6jUQgH560Y6mQQx/bq4M+IrkeicWBg03o70Jkihbhx88Y7xf/zlteQTyatGYT0aAPAzqQXm/8s/2IAFgKtRILXOxrGHknve+rN1TBZP8d9L2ohQTltie8zTd+i/DQ/RhNn320YghDhX+/h2ayoYWKqagk7sO4R6YYP0FrtHGh8lO0At7+Tmo9hdtIiqznIZrQq6OMUK9Xxg4EgamYKFWBDwh3MIabb2D1H58OeMjkh2TwWi9YH7e6xM6H7UxuCNYVlcENuDAh1una6hVG+QkInKl3tW6cOsi1JgSxAEGKqNjvCeiy/uWKFELz+AwGklPIVLZy3OMW2YzuPNwUp0XxnsixldOwcB1x1C7fka/08UWDQUVovJARlR6CTNU7s4up5M0rucOfcbp8K0pBqY=",
      "importKeyParams": {"hash": "sha-384"},
      "signVerifyParams": {}
    }
  ]);
}
