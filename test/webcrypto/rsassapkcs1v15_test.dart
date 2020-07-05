import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';
import '../utils.dart';
import '../testrunner.dart';

final runner =
    TestRunner.asymmetric<RsassaPkcs1V15PrivateKey, RsassaPkcs1V15PublicKey>(
  algorithm: 'RSASSA-PKCS1-v1_5',
  importPrivateRawKey: null, // not supported
  exportPrivateRawKey: null,
  importPrivatePkcs8Key: (keyData, keyImportParams) =>
      RsassaPkcs1V15PrivateKey.importPkcs8Key(
          keyData, hashFromJson(keyImportParams)),
  exportPrivatePkcs8Key: (key) => key.exportPkcs8Key(),
  importPrivateJsonWebKey: (jsonWebKeyData, keyImportParams) =>
      RsassaPkcs1V15PrivateKey.importJsonWebKey(
          jsonWebKeyData, hashFromJson(keyImportParams)),
  exportPrivateJsonWebKey: (key) => key.exportJsonWebKey(),
  importPublicRawKey: null, // not supported
  exportPublicRawKey: null,
  importPublicSpkiKey: (keyData, keyImportParams) =>
      RsassaPkcs1V15PublicKey.importSpkiKey(
          keyData, hashFromJson(keyImportParams)),
  exportPublicSpkiKey: (key) => key.exportSpkiKey(),
  importPublicJsonWebKey: (jsonWebKeyData, keyImportParams) =>
      RsassaPkcs1V15PublicKey.importJsonWebKey(
          jsonWebKeyData, hashFromJson(keyImportParams)),
  exportPublicJsonWebKey: (key) => key.exportJsonWebKey(),
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
  testData: _testData,
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

  runner.runTests();
}

// Allow single quotes for hardcoded testData written as JSON:
// ignore_for_file: prefer_single_quotes
final _testData = [
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
    "name": "generated on boringssl/linux at 2020-01-14T19:37:46",
    "generateKeyParams": null,
    "privateRawKeyData": null,
    "privatePkcs8KeyData":
        "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCvb+7BcH5UxZkBihgoPosQf/tkaZUrulsjmuiGM7y2AA4PGjm4oUXicx6427H6U4l5+BGxDgQuFyloWk2meL/zilHHql89B9QhSWGe9fdF3FYtBnNIIKV1WADkNCTR/tJjtkV5YdL4Xin/oFKsWTiHZc6V1QYtXtRW20jv+qWEaAjLpC7fvKh0XdRMYj6y4sBLcJlLLP5+/UiM8l1Fs6/rWxoBG6cibIj334NmtSP7Hrs2JW8UW6ZBxwmlL2tG8mrXx3mc1wvg4zC3g/D7L8CtcX1NgTyj9Aye7ZBy9wvFV2OMAb8gpW7grg3ZiU+3To/gXvbOUhtB3y7ahtL4ISQFAgMBAAECggEAEPod+q4uK3nrspBwggR7ZJ9d7nuhKdgg1bM56TK8gkhDFAcPquRAZQeK44yvDnBjD2CIJcAbe3JWWXjTptZsjN7HxzCfgsJtLsNxJPbcdPA7jqPfKA2wtUhM3ciF/6RPK8MJuhNTXSGPouMa3P7NT5z0ft9cd6uDlNwnlMGGnudhPuXycUi2Wyp2pitHiZAU01wRrt2T+NTFB8H/L+GKIhwZ5hihnj/RdvZi7FKaoxOaAcMRtsXf0Fteztzo5PhsFyeY4g6UeqZC0WUAfjSh0n2VaKPPIrwoOGGQg+EIaZgC+bEFFucrSpZZnz0IdCwcDGA/dXBJHwC3bKgM42ErwQKBgQDk95gYMvav6v32vg4AtYCSrsStfRm47mUjsPt9ug0va4DmSXhEN6ssVkTm9hjwPAZeE52ioArgKLIr1I2MI3xuz7rmtQrF5ZToOovFiaxhFlB9W0vxpLUf20uvovL9KzyKEKG8xoHGvbdNNDeupGuZYHelUeueriIYXc/62AiebQKBgQDEJm0S6Vsta7Z/emQoey3EhaB+8OaDOi54zIDOMXGfRbdTWy3aSJaV61FkYi2kTJurobhW6lyeIGFaX9ySxW+lBRMckR0lEwLSEZqGimnxGqoquZDusub4NNOnRfumMNBPr13MQ9jPix9Fd0aAKtdUIPOD9LNmukERGnwrtKO8+QKBgBzeVs/eRRojD8g3aD6Qo9harrONDVwyuo/Idb0BYz4yWLswUjiPqEZbzi4sozJO7yKXaI2jjht7JhO+peYgZ0T1bgQ+mVAgRSkOkKbkV9aZ4KYdh7K86JVOqflIG0juVaC2vh22DZDIRL84MTkUw/g/oHY4oPON0wCte1aOPG/1AoGAJA5oOHS69PN63Z4S8ToLZLenlA4WYYL9bekxuDVwjHWVSHZXTGvReoeCM7C0cSI/72HP7/IuykZrfuBmPHicmDoBlFu8fscq2pCv1hF1fgOHykjIMoiiWnfjfDkqFBefAzbaSCUkoqoROoS9aev2HxnbiaMeo0CTm2BB+QrAmokCgYBcjp9bTz+eYBg/iF4D5SdybZsHj2bBOR5zjXMsErrOGWQSMVgTzJW01weYJEc5aC+9UAcXTPhglvXceUGqMxQswJIcvi9qAHCNI/iaOaHcy7ugCyGka+CHCFQcA+AMAOJf4/Dld39VdGDg7WUgCuaAb7KpKVhXC71Ened9CQtSiw==",
    "privateJsonWebKeyData": {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "d":
          "EPod-q4uK3nrspBwggR7ZJ9d7nuhKdgg1bM56TK8gkhDFAcPquRAZQeK44yvDnBjD2CIJcAbe3JWWXjTptZsjN7HxzCfgsJtLsNxJPbcdPA7jqPfKA2wtUhM3ciF_6RPK8MJuhNTXSGPouMa3P7NT5z0ft9cd6uDlNwnlMGGnudhPuXycUi2Wyp2pitHiZAU01wRrt2T-NTFB8H_L-GKIhwZ5hihnj_RdvZi7FKaoxOaAcMRtsXf0Fteztzo5PhsFyeY4g6UeqZC0WUAfjSh0n2VaKPPIrwoOGGQg-EIaZgC-bEFFucrSpZZnz0IdCwcDGA_dXBJHwC3bKgM42ErwQ",
      "n":
          "r2_uwXB-VMWZAYoYKD6LEH_7ZGmVK7pbI5rohjO8tgAODxo5uKFF4nMeuNux-lOJefgRsQ4ELhcpaFpNpni_84pRx6pfPQfUIUlhnvX3RdxWLQZzSCCldVgA5DQk0f7SY7ZFeWHS-F4p_6BSrFk4h2XOldUGLV7UVttI7_qlhGgIy6Qu37yodF3UTGI-suLAS3CZSyz-fv1IjPJdRbOv61saARunImyI99-DZrUj-x67NiVvFFumQccJpS9rRvJq18d5nNcL4OMwt4Pw-y_ArXF9TYE8o_QMnu2QcvcLxVdjjAG_IKVu4K4N2YlPt06P4F72zlIbQd8u2obS-CEkBQ",
      "e": "AQAB",
      "p":
          "5PeYGDL2r-r99r4OALWAkq7ErX0ZuO5lI7D7fboNL2uA5kl4RDerLFZE5vYY8DwGXhOdoqAK4CiyK9SNjCN8bs-65rUKxeWU6DqLxYmsYRZQfVtL8aS1H9tLr6Ly_Ss8ihChvMaBxr23TTQ3rqRrmWB3pVHrnq4iGF3P-tgInm0",
      "q":
          "xCZtEulbLWu2f3pkKHstxIWgfvDmgzoueMyAzjFxn0W3U1st2kiWletRZGItpEybq6G4VupcniBhWl_cksVvpQUTHJEdJRMC0hGahopp8RqqKrmQ7rLm-DTTp0X7pjDQT69dzEPYz4sfRXdGgCrXVCDzg_SzZrpBERp8K7SjvPk",
      "dp":
          "HN5Wz95FGiMPyDdoPpCj2Fqus40NXDK6j8h1vQFjPjJYuzBSOI-oRlvOLiyjMk7vIpdojaOOG3smE76l5iBnRPVuBD6ZUCBFKQ6QpuRX1pngph2HsrzolU6p-UgbSO5VoLa-HbYNkMhEvzgxORTD-D-gdjig843TAK17Vo48b_U",
      "dq":
          "JA5oOHS69PN63Z4S8ToLZLenlA4WYYL9bekxuDVwjHWVSHZXTGvReoeCM7C0cSI_72HP7_IuykZrfuBmPHicmDoBlFu8fscq2pCv1hF1fgOHykjIMoiiWnfjfDkqFBefAzbaSCUkoqoROoS9aev2HxnbiaMeo0CTm2BB-QrAmok",
      "qi":
          "XI6fW08_nmAYP4heA-Uncm2bB49mwTkec41zLBK6zhlkEjFYE8yVtNcHmCRHOWgvvVAHF0z4YJb13HlBqjMULMCSHL4vagBwjSP4mjmh3Mu7oAshpGvghwhUHAPgDADiX-Pw5Xd_VXRg4O1lIArmgG-yqSlYVwu9RJ3nfQkLUos"
    },
    "publicRawKeyData": null,
    "publicSpkiKeyData":
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr2/uwXB+VMWZAYoYKD6LEH/7ZGmVK7pbI5rohjO8tgAODxo5uKFF4nMeuNux+lOJefgRsQ4ELhcpaFpNpni/84pRx6pfPQfUIUlhnvX3RdxWLQZzSCCldVgA5DQk0f7SY7ZFeWHS+F4p/6BSrFk4h2XOldUGLV7UVttI7/qlhGgIy6Qu37yodF3UTGI+suLAS3CZSyz+fv1IjPJdRbOv61saARunImyI99+DZrUj+x67NiVvFFumQccJpS9rRvJq18d5nNcL4OMwt4Pw+y/ArXF9TYE8o/QMnu2QcvcLxVdjjAG/IKVu4K4N2YlPt06P4F72zlIbQd8u2obS+CEkBQIDAQAB",
    "publicJsonWebKeyData": {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "n":
          "r2_uwXB-VMWZAYoYKD6LEH_7ZGmVK7pbI5rohjO8tgAODxo5uKFF4nMeuNux-lOJefgRsQ4ELhcpaFpNpni_84pRx6pfPQfUIUlhnvX3RdxWLQZzSCCldVgA5DQk0f7SY7ZFeWHS-F4p_6BSrFk4h2XOldUGLV7UVttI7_qlhGgIy6Qu37yodF3UTGI-suLAS3CZSyz-fv1IjPJdRbOv61saARunImyI99-DZrUj-x67NiVvFFumQccJpS9rRvJq18d5nNcL4OMwt4Pw-y_ArXF9TYE8o_QMnu2QcvcLxVdjjAG_IKVu4K4N2YlPt06P4F72zlIbQd8u2obS-CEkBQ",
      "e": "AQAB"
    },
    "plaintext": "dW0gbmVjIG5pcw==",
    "signature":
        "L6HPn8S+F2VPGbeKv80GNEuHawJKFkrnengDtoG6M9eVhW0aUYW1r8KAyal1wV5dvU3/mFap/NKHa/WD8f95ndDa9sQ6mj2GYadcB0d92OZvQ6RvAmX53Ia2KpSEKlvqOiOJvxGct4x4POx9yzxQxz9TwYkVNu1WSJTtCfIWNZZDbUK7yghgVRuAD0iqUTuTYN9TqVAM4Sp1wWdu2I4ZpjJZcMudFmQGIMrmhobOlTLS18QtxUO6XZopmTNTrFXcVtRazlMZDcfmWsyw54Qk1LPWW2EdZNe2plG81EWBAAtSz6KoSterwgHXX0BSwNsku7HlH0GcckJctQ/CODVqdQ==",
    "importKeyParams": {"hash": "sha-256"},
    "signVerifyParams": {}
  },
  {
    "name": "generated on chrome/linux at 2020-01-14T19:38:37",
    "generateKeyParams": null,
    "privateRawKeyData": null,
    "privatePkcs8KeyData":
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCdq6XMz1s7Z+FCJ4DYcirYQB6Ku7dZ4uhDiWw0jwmcQpItNIxE/zJ4HKXouB5+StPuiJ+wMOmhl6XA6vaqLAiqNAvtkxg1ZnCdt9sfFtKAEjZsoyKDHL0Le+zhK/13zaaD2PHy8nYyXHgrFQV8X1NVypIkBV3D4JsXLK6GBDVAD+5edndgJTiRj+oNpPNVWQtiHcxM0QDFahE6/Oe0pGmPgByCGxsYgXZutKyQwSQkKfh22m1hQSH68tFJ5rPkGT+NZ4ivU0hHjv3JZWgOm65NvjNxN7yjRo4D1AYKBOn/PrACrSCWxX9hVY+V27DYTS9iBiB7cPjQQvspFsJtXQj3AgMBAAECggEAAiQkmkVunb3pZzaWH1pdjpZAU+38rXHRaaliGMygesjEp2yBQyacDtmEv0ZQ07I8co7UbFYdth4TGC2Yr/LtIzKVvuIyf/cmLF4k0aVDso2Mw6jrfRBU2OUT8HLifFAEpOG7V2tHg6OR1jPw4SGCRjX8ChUwkspoEMaAkD1aY8ZOJeq3FJqKpYBtZCg8AGmtzK0kg28XQ755IdlMWOrTd+jU3gXMvIbcgdRYLv7XGBhzmAd9af2UmhlST8p/6xedTRJ6hkAUnez5RmEBVZEE2dcVWaZdiiP2VsSNcUre+lW0nnIdED/m32i3SffyXX6sBmY4hoNvTt/Uw+T7VP3DEQKBgQDSmVt2S9L5e1S/RwnNt/awBPEt4KEwTxZ9JpmTo5yzSthsLCIzssUqUPBDXB9mkJChN2B3taCaaYlkRcJ3BgGg2P5h1pkqyO1EqhWBNu5qkuZ0MceIhhzQAxCsrMaFQnjZ2UmpuEQNkZ1iwIORwv7PThA6DcjnGjklYCEyfK7TSwKBgQC/qT5if26mn/1a7mh5/rLVy+64uDzYRqdRQSLXKyfRGEWq6aCq5iOM7J+W17eTT9i2B/ANaAh8J5UHclyy6uIBdJ4xkTfaL1xYFgbsbkx/T9wBxPw63y0OVRKtZlunssvj7MX6gQhQEWt2Rb5s6CLKxabSFRMfbcz1gR80em7phQKBgH32qkUcXylHwk3SUKPSN+PaYOM+60p404uxrcQn5U88Iiy5TQ+9Cr8fwEWZ8VIof8ld1P5lDZWuMDZgn0sPtaOehrDAaca0fW5HiStLTtlB2kN/jsgy50Lnwm51vRvxwVUT6UJxa4ruIMPzP/7MMhqOp5gBrLvF7I5VbCXFe8/3AoGAHUSjGjeLljZoYjJ2EesrNCroUZ0Q7ZYchvQDdghJFE04llkHCBIM68BWvppClmRjG6kqp2FzqkIBKBn2vfvQd5hvb/JVLSR+XZU/iWtukyKG3l5Ohk7+emnTaFdxN7K+IBhQQ2jg9Bk05+LOqaLpbT2xs/Mz8GC8I+GL+l+YAGECgYEAl/+v+oqtL2V/M8s5lvkxhcEUBTve3b6wefEVNq/YAPCviCHtzZNwZN/SsfK+MzbyY7XaOJVC6S1H/05oB/jQTZuA8UaMW52MYrKYERPSZ7SRvVFuevCeq6hhc0Ixy2H6y3qQ4bjPtXI74ZUsVQ2DTCLUsT5OHLaWlLhXTXwaxbg=",
    "privateJsonWebKeyData": {
      "kty": "RSA",
      "alg": "RS256",
      "d":
          "AiQkmkVunb3pZzaWH1pdjpZAU-38rXHRaaliGMygesjEp2yBQyacDtmEv0ZQ07I8co7UbFYdth4TGC2Yr_LtIzKVvuIyf_cmLF4k0aVDso2Mw6jrfRBU2OUT8HLifFAEpOG7V2tHg6OR1jPw4SGCRjX8ChUwkspoEMaAkD1aY8ZOJeq3FJqKpYBtZCg8AGmtzK0kg28XQ755IdlMWOrTd-jU3gXMvIbcgdRYLv7XGBhzmAd9af2UmhlST8p_6xedTRJ6hkAUnez5RmEBVZEE2dcVWaZdiiP2VsSNcUre-lW0nnIdED_m32i3SffyXX6sBmY4hoNvTt_Uw-T7VP3DEQ",
      "n":
          "naulzM9bO2fhQieA2HIq2EAeiru3WeLoQ4lsNI8JnEKSLTSMRP8yeByl6LgefkrT7oifsDDpoZelwOr2qiwIqjQL7ZMYNWZwnbfbHxbSgBI2bKMigxy9C3vs4Sv9d82mg9jx8vJ2Mlx4KxUFfF9TVcqSJAVdw-CbFyyuhgQ1QA_uXnZ3YCU4kY_qDaTzVVkLYh3MTNEAxWoROvzntKRpj4AcghsbGIF2brSskMEkJCn4dtptYUEh-vLRSeaz5Bk_jWeIr1NIR479yWVoDpuuTb4zcTe8o0aOA9QGCgTp_z6wAq0glsV_YVWPlduw2E0vYgYge3D40EL7KRbCbV0I9w",
      "e": "AQAB",
      "p":
          "0plbdkvS-XtUv0cJzbf2sATxLeChME8WfSaZk6Ocs0rYbCwiM7LFKlDwQ1wfZpCQoTdgd7WgmmmJZEXCdwYBoNj-YdaZKsjtRKoVgTbuapLmdDHHiIYc0AMQrKzGhUJ42dlJqbhEDZGdYsCDkcL-z04QOg3I5xo5JWAhMnyu00s",
      "q":
          "v6k-Yn9upp_9Wu5oef6y1cvuuLg82EanUUEi1ysn0RhFqumgquYjjOyflte3k0_YtgfwDWgIfCeVB3JcsuriAXSeMZE32i9cWBYG7G5Mf0_cAcT8Ot8tDlUSrWZbp7LL4-zF-oEIUBFrdkW-bOgiysWm0hUTH23M9YEfNHpu6YU",
      "dp":
          "ffaqRRxfKUfCTdJQo9I349pg4z7rSnjTi7GtxCflTzwiLLlND70Kvx_ARZnxUih_yV3U_mUNla4wNmCfSw-1o56GsMBpxrR9bkeJK0tO2UHaQ3-OyDLnQufCbnW9G_HBVRPpQnFriu4gw_M__swyGo6nmAGsu8XsjlVsJcV7z_c",
      "dq":
          "HUSjGjeLljZoYjJ2EesrNCroUZ0Q7ZYchvQDdghJFE04llkHCBIM68BWvppClmRjG6kqp2FzqkIBKBn2vfvQd5hvb_JVLSR-XZU_iWtukyKG3l5Ohk7-emnTaFdxN7K-IBhQQ2jg9Bk05-LOqaLpbT2xs_Mz8GC8I-GL-l-YAGE",
      "qi":
          "l_-v-oqtL2V_M8s5lvkxhcEUBTve3b6wefEVNq_YAPCviCHtzZNwZN_SsfK-MzbyY7XaOJVC6S1H_05oB_jQTZuA8UaMW52MYrKYERPSZ7SRvVFuevCeq6hhc0Ixy2H6y3qQ4bjPtXI74ZUsVQ2DTCLUsT5OHLaWlLhXTXwaxbg"
    },
    "publicRawKeyData": null,
    "publicSpkiKeyData":
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnaulzM9bO2fhQieA2HIq2EAeiru3WeLoQ4lsNI8JnEKSLTSMRP8yeByl6LgefkrT7oifsDDpoZelwOr2qiwIqjQL7ZMYNWZwnbfbHxbSgBI2bKMigxy9C3vs4Sv9d82mg9jx8vJ2Mlx4KxUFfF9TVcqSJAVdw+CbFyyuhgQ1QA/uXnZ3YCU4kY/qDaTzVVkLYh3MTNEAxWoROvzntKRpj4AcghsbGIF2brSskMEkJCn4dtptYUEh+vLRSeaz5Bk/jWeIr1NIR479yWVoDpuuTb4zcTe8o0aOA9QGCgTp/z6wAq0glsV/YVWPlduw2E0vYgYge3D40EL7KRbCbV0I9wIDAQAB",
    "publicJsonWebKeyData": {
      "kty": "RSA",
      "alg": "RS256",
      "n":
          "naulzM9bO2fhQieA2HIq2EAeiru3WeLoQ4lsNI8JnEKSLTSMRP8yeByl6LgefkrT7oifsDDpoZelwOr2qiwIqjQL7ZMYNWZwnbfbHxbSgBI2bKMigxy9C3vs4Sv9d82mg9jx8vJ2Mlx4KxUFfF9TVcqSJAVdw-CbFyyuhgQ1QA_uXnZ3YCU4kY_qDaTzVVkLYh3MTNEAxWoROvzntKRpj4AcghsbGIF2brSskMEkJCn4dtptYUEh-vLRSeaz5Bk_jWeIr1NIR479yWVoDpuuTb4zcTe8o0aOA9QGCgTp_z6wAq0glsV_YVWPlduw2E0vYgYge3D40EL7KRbCbV0I9w",
      "e": "AQAB"
    },
    "plaintext": "bmV0dXMgZXQgbWFsZXN1YWRhCmZhbWVzIGFjIHR1cg==",
    "signature":
        "a56s/BVGj4EGbxndBFJyjyE+DMLGGCndN1il4mgzt2lQ58Iu5L1s6w8IRi1oBGTwzmIk+Jecxk+ivXiuQvLSJr/DTLTZpLTO+BIhec8fIk339hnZKz1VHphxzH942P8Jy+2jXZuoIhQ4ueZBy0yAw2m2i0DKpjgV4y3YZQbb8AbU3TDHUjbdYHFihc8cRwdDbyQumOt1k+iTsBuj1wf43YeJhgq7B1Ue5rz+P5aO8n7WZHCQuNSDH/F+U5gDrurv6FHMt4wI82oOYQyFUOce6wcyh6yKogHKf+gTzTbYL7lefWqyQZK2KmzCnCugRtRx4KqAKs+EiWN2BvErewGy5A==",
    "importKeyParams": {"hash": "sha-256"},
    "signVerifyParams": {}
  },
  {
    "name": "generated on firefox/linux at 2020-01-14T19:39:01",
    "generateKeyParams": null,
    "privateRawKeyData": null,
    "privatePkcs8KeyData":
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDMvTxgUJ7QR7MMiU3n5Wweg1JnOXPPLcsu6tPgPdmAMZJSTxXE/XDWb6ptmr/BWl5M+iy3EUQ881OTNk1LA5LbwX+BzyFjPOGxf7Y9CDBDLWKOLt8xZtyuvABVsQN21DJCuCCOISQZjFe+m14NLWDsunk0p0DhV5xu8DgTRAURX5NUejPcwFp0b+R56F+S8LGL04FBLhiYNc+VQQpOg6j8ez15AbEhdFaI1MHD3x36Tv8HX/XcEL9u1LhcUqi5ISgF9dJdmEtXJ+2rUnf9Dmo+d4CmlL4qfSeGcwb0Z+JHrqkE+Dpqq3kdbXzIT6+9HaJRwTZwKuU/zI90oO2+GYUbAgMBAAECggEAHdYD6utEwYh5VL3bnwwlberoQseyE0KSpgMtnjOVMyPGNX116C+g1ncOaIuRHy26qVAZ3RHElndFOiJDMEfUinbPzIxxSqNwJmw8k/dSBTAjeSHmf64EQeh+yf4SSapRqrxnbh7xQlHb5ZiBo7z1r3nbOOuYvl4Em3whR9l1PZsjtLO+k0lKbcR18wyM93T5UunzXOIzXLu+HmhxIxk+98VxUCsfhVJwEtLwSJWw4eSRZ1IUjnm+ta6c3kOljG0GeyTZZyVYkDNYAJ89fxrgLmyGuW1beAyax99THZ44FNUvu0mczecKh3j6KjVAO/fAwVkufFMmfUwxSNvPweJM1QKBgQDvGzPQqFnoEksel2B8Ygn69VOzNfWMLbAv5lDAdhbOmSlxSuKXggAYugfID+uFCayPHizDpDPUdJlqiiBligq15SAh+dabSmqxQYFA4AbQxpkafe4UhghDYQWe7jlCv1sdRl/vXqDjFJgzI2+TMOWAqXmxizvewzHWevFxdJ3DTQKBgQDbNGyymZQrkDX2ZsXOasLaq5ZajzhGG9HthUutsUeh+gTaFsNC8a3cf8Qj64TM4rXxctERGWr9/1ssc8oF9atuCTX1HhWDrEw4nxJxGLRBZIzeOBakkL1ZbnsyoV+XILfjYj4sNSaZWDPFbIwX2dwlAVccUJrxg2hvNPmtpJrmBwKBgQDkBqkvgJ3dODTzg6G8fTLPZk7gRcFaYef4hkjUgsnVVTO0m5nkq1G0QxVQsf4F7efmxPwjx+C16Ey20et7al40gcJXJJCJoDqHuNSvLfbR+9Pe8+GtKPWQbGKT4tQw15TpIkgzW6dLaESN4GlzkdoNDZLEwufh1X0d8jl33aLmsQKBgGVP+5UoalUgF/DEW1Ql/901RQ6h9y5gGUygOPQUZbk1ZxytPJ4qOWMaIjs/1WckuVbY7Evs5Yhzh14qPgs3Gn6G/0tFFkh/T9MzokBnXJiEsp7aaYyx4PH+oC4sa5Pb6WHMvFOOVUK2g2cR3kX/yUHJNsu9bX+GbrRHVcatt3HtAoGAQ02/5gFeNYr9G8rJIcj0PsEl3VS/wAtygjjchdi57fhsXZKvIaeVj4/L3Aeg86GZ2+sXcCHHCbBSCJzS8MJxUSo8inhoMONOlRC2QhaMnTbW+xzjP4JOF5DN++qTwP8dM1MM5oVVTFwz1W4HzahZLPW2BHJeMS/SsOK1dfArnzo=",
    "privateJsonWebKeyData": {
      "kty": "RSA",
      "alg": "RS256",
      "d":
          "HdYD6utEwYh5VL3bnwwlberoQseyE0KSpgMtnjOVMyPGNX116C-g1ncOaIuRHy26qVAZ3RHElndFOiJDMEfUinbPzIxxSqNwJmw8k_dSBTAjeSHmf64EQeh-yf4SSapRqrxnbh7xQlHb5ZiBo7z1r3nbOOuYvl4Em3whR9l1PZsjtLO-k0lKbcR18wyM93T5UunzXOIzXLu-HmhxIxk-98VxUCsfhVJwEtLwSJWw4eSRZ1IUjnm-ta6c3kOljG0GeyTZZyVYkDNYAJ89fxrgLmyGuW1beAyax99THZ44FNUvu0mczecKh3j6KjVAO_fAwVkufFMmfUwxSNvPweJM1Q",
      "n":
          "zL08YFCe0EezDIlN5-VsHoNSZzlzzy3LLurT4D3ZgDGSUk8VxP1w1m-qbZq_wVpeTPostxFEPPNTkzZNSwOS28F_gc8hYzzhsX-2PQgwQy1iji7fMWbcrrwAVbEDdtQyQrggjiEkGYxXvpteDS1g7Lp5NKdA4VecbvA4E0QFEV-TVHoz3MBadG_keehfkvCxi9OBQS4YmDXPlUEKToOo_Hs9eQGxIXRWiNTBw98d-k7_B1_13BC_btS4XFKouSEoBfXSXZhLVyftq1J3_Q5qPneAppS-Kn0nhnMG9GfiR66pBPg6aqt5HW18yE-vvR2iUcE2cCrlP8yPdKDtvhmFGw",
      "e": "AQAB",
      "p":
          "7xsz0KhZ6BJLHpdgfGIJ-vVTszX1jC2wL-ZQwHYWzpkpcUril4IAGLoHyA_rhQmsjx4sw6Qz1HSZaoogZYoKteUgIfnWm0pqsUGBQOAG0MaZGn3uFIYIQ2EFnu45Qr9bHUZf716g4xSYMyNvkzDlgKl5sYs73sMx1nrxcXSdw00",
      "q":
          "2zRsspmUK5A19mbFzmrC2quWWo84RhvR7YVLrbFHofoE2hbDQvGt3H_EI-uEzOK18XLRERlq_f9bLHPKBfWrbgk19R4Vg6xMOJ8ScRi0QWSM3jgWpJC9WW57MqFflyC342I-LDUmmVgzxWyMF9ncJQFXHFCa8YNobzT5raSa5gc",
      "dp":
          "5AapL4Cd3Tg084OhvH0yz2ZO4EXBWmHn-IZI1ILJ1VUztJuZ5KtRtEMVULH-Be3n5sT8I8fgtehMttHre2peNIHCVySQiaA6h7jUry320fvT3vPhrSj1kGxik-LUMNeU6SJIM1unS2hEjeBpc5HaDQ2SxMLn4dV9HfI5d92i5rE",
      "dq":
          "ZU_7lShqVSAX8MRbVCX_3TVFDqH3LmAZTKA49BRluTVnHK08nio5YxoiOz_VZyS5VtjsS-zliHOHXio-Czcafob_S0UWSH9P0zOiQGdcmISyntppjLHg8f6gLixrk9vpYcy8U45VQraDZxHeRf_JQck2y71tf4ZutEdVxq23ce0",
      "qi":
          "Q02_5gFeNYr9G8rJIcj0PsEl3VS_wAtygjjchdi57fhsXZKvIaeVj4_L3Aeg86GZ2-sXcCHHCbBSCJzS8MJxUSo8inhoMONOlRC2QhaMnTbW-xzjP4JOF5DN--qTwP8dM1MM5oVVTFwz1W4HzahZLPW2BHJeMS_SsOK1dfArnzo"
    },
    "publicRawKeyData": null,
    "publicSpkiKeyData":
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzL08YFCe0EezDIlN5+VsHoNSZzlzzy3LLurT4D3ZgDGSUk8VxP1w1m+qbZq/wVpeTPostxFEPPNTkzZNSwOS28F/gc8hYzzhsX+2PQgwQy1iji7fMWbcrrwAVbEDdtQyQrggjiEkGYxXvpteDS1g7Lp5NKdA4VecbvA4E0QFEV+TVHoz3MBadG/keehfkvCxi9OBQS4YmDXPlUEKToOo/Hs9eQGxIXRWiNTBw98d+k7/B1/13BC/btS4XFKouSEoBfXSXZhLVyftq1J3/Q5qPneAppS+Kn0nhnMG9GfiR66pBPg6aqt5HW18yE+vvR2iUcE2cCrlP8yPdKDtvhmFGwIDAQAB",
    "publicJsonWebKeyData": {
      "kty": "RSA",
      "alg": "RS256",
      "n":
          "zL08YFCe0EezDIlN5-VsHoNSZzlzzy3LLurT4D3ZgDGSUk8VxP1w1m-qbZq_wVpeTPostxFEPPNTkzZNSwOS28F_gc8hYzzhsX-2PQgwQy1iji7fMWbcrrwAVbEDdtQyQrggjiEkGYxXvpteDS1g7Lp5NKdA4VecbvA4E0QFEV-TVHoz3MBadG_keehfkvCxi9OBQS4YmDXPlUEKToOo_Hs9eQGxIXRWiNTBw98d-k7_B1_13BC_btS4XFKouSEoBfXSXZhLVyftq1J3_Q5qPneAppS-Kn0nhnMG9GfiR66pBPg6aqt5HW18yE-vvR2iUcE2cCrlP8yPdKDtvhmFGw",
      "e": "AQAB"
    },
    "plaintext":
        "aW5pYSB1cm5hIGVuaW0gZWdldCBmZWxpcy4gVmVzdGlidWx1bSB2ZXN0aWJ1bHVtIGx1Y3R1cyA=",
    "signature":
        "yOJiop9wl46od4Ho7m1NBNPrao52N7tJn3ezDBVWvCBGQl1RXpdSkSwRfqpbr0aebUTUw/OkHwEPjI+wXwHFogt6Ddsk9hE86VIoS1+8/QxSfjP2uLOrmkHCbWr1JQVH7slpmiLXmsfVUoAyo2MHIIC2sl1EK8HnLAm4NUj2Zk4bBqnk/W1m+l/deEwY5pH8m0I/OYWbVrIUNKoxhQls8Dl8Q2ewi5QBsoZngf7jecW+l0SU1H0DXXYpPAO5aoWptZ3JZlXCItTxfwmjhLk8c9U4cEziVqhTey9l06bXOFk/h3d4+aeZS6X7uWACtGMbGycIvaLSFA2EVUWdcKLXUw==",
    "importKeyParams": {"hash": "sha-256"},
    "signVerifyParams": {}
  },
  {
    "name": "4096/384 generated on boringssl/linux at 2020-01-14T19:40:49",
    "generateKeyParams": null,
    "privateRawKeyData": null,
    "privatePkcs8KeyData":
        "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",
    "privateJsonWebKeyData": {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS384",
      "d":
          "AlbsqGEyicZoxw7LCXgEt48u-0rH_EiD4gbFqE2CBnLh3OTiu4yurXkboT6orBAOKuhYkpG-luvxMewyvSlxkIF-_UWdB4Jc7XTI7JcXjFsfjlsCgvlB_NC6LH9hEDSBwaueeqM6Y38Lph_873s1Ae2xSCUtiQ2ES-98GPKkIx-dSFVg3BYgDWCcr1mJMpGkUeqNseiu-T9sNow2w6MFFYAW0Z0Q0WaNoTSlf9xF7VBbYuUR7rUFLbnXpariwgd3Azt5NJKmYwkwoOjOjKPwctzFTkpW9GPFpcl9fSaGzV5aXO-q-LiZ-Ri3mLC_yKzqpDnJxKQyld0p2rLBRLQ0B5LXhrWWDJsi3FPmtFmSxSzAsabze3NbbS-T0xX7eqIYo2wGtA7AEqszuCK1G3hyTBqTTQEJNWFbUgrSPyb63AmHC6ATLopav3QFLgIUS_ULQDOlcWfYSoZGw6drZhAnKxeyFQCz6fuHqZS_t3HQzIojy3pUjtuH1CpJU-Sxyz8ebjua7RSiXLoKWntOJdk4uGECZGnf-jJKd8GzKjQuhDNghGTrqglAjJE8lVsmm7BTT6_ojZTvqo4Dy0VAaVpXYesLyXG5VpdBsv8CyKHtn77sn2HQ26nAdSEkzrTGwJ6reJniN8ZKD5IkmDT-VrJCbWv49A5AsU9i9b5TkHWugTE",
      "n":
          "1OlzfQdInFgNUajjmoDabCI3n-9KELvBUo2S5Ii5cjrrDGdDPWR62ZUJHTOeCoRSgphEehhHvXWa_oPDvw_ZSPJc5vmOVtO4OrSEuq-oqL0WNdQgZOAyGT1Xu3yEf7hhq0Yva-mdIMHkfDBrEPYrXdfNqqTU3XxXQS3eiPjRpwpaElBbhl4zuVefs2Uz_SZaVtiBJ5fnF3NXSVS3YJB7SMibZMOrj3F2FnFlflHJncixEfy9PfBraykqbuXLaKSAuvRssXzpzCbh67Bh0Nfpoq_fXi3X1eejHMrgfO7efxCcxScfEMJXcYsjsYKHsTrRiGeyqC7aMCe20o_opnveNSCFeCazRNMOInCmTDEzGocUIc0ZFqveanOpgfYfWUPhYxkZnaBDcb0B81_mM9cBrnvCCdSCxo5Oeuw6mGCKQbLKcUKSOnTz2hW6totX1o-K4cvqOFm1FilkC0SOz9oIlW3Ldg4k865USjVFefPYv_6wl6giielNUhvGJ3BLA5N9tCCmjop1ydjRh8mq0MErqXaA0lOVAoRqbp7YIpU_hrMpmqamNDPFjOVIaExbhzZdiGpBkP-vH1pv3Ez4hvwJdaLy3LVphnNEMO4NEmwqzjx2kF98uYB5sjvkujGjeDRaC3HO3m4-oYOZLOkYuoHwf9nYsGOPdZaZTpFB92S5Ixc",
      "e": "AQAB",
      "p":
          "_iwbryc78TdbbRllVdc6t0K1HZStVDZY8Cfc3r01Ca5pDYGKryWHRmsZOU88iBBSm-BLtLt7IHNxM9WOhbsIdUuzBoqa4uhcPp82PqptGUa1lZJAuJdoOpT-5jzLAiHYrGdsc9ZMe0pzat8pveM-7FtPQacNOJFkDNh3opnjRRJPum7BjWiCN_zYnJLyN2Qf-dmoaJyCCf67sRUl1OlZFBKi44VbELHwa5XEU_t9540DerUHow2C59R3ii5JC2YaeT83Jw5Wi8HygTeyerM0iNKT-ZPjskyAMIf_3dXPZg4ZUa3bNk3QsZepCHW0NeyBRw0_n05kdX2JEEuQ0r2ULw",
      "q":
          "1nFjlmhd-vabK7Vwe7DSuhQcn-D_3wnWP3PmkbkrO-5JFQvHq_Q513-tKDriCUys3mroAJ-WFUs6uhHDSVxyVfGCrGF-n9tqxvy3W8DZXpP3yhkHKxnkRczJrNAlZxRa8Z-2v-qrqbGJqBDTmhGDEuza98_slfspfCQdFPNrcjww11uqAKcGlW1Bc91p28u94-AyGcF6VvDWKerV-1hT2TxTBF1LyQhMxULOuQ-M9mZ6jG-Eag0zCGVpKbBhoIt_RSDPOFr5QLvlGSttZtahetXMGXIV1G5KnO4ssAQCY-xtWkoqzUCLeqZv9uOhR2atvHTLMJA9121VoJfD7LHdmQ",
      "dp":
          "opwFeiFXsBMCYuIEes6fue7rgGlGGsJKVBqsq7PQ4si6XPGrkDIqQVrzYD7ZMxN-RktRI-dt9mzk14yhCd2Go8QyXNUAEnslyMqDIcRW1_zs3ywaS_5RqGj6SsJJ_qs4u9PPBqzrcVVIUe9D_UANWZlxM0d0peQeZjl3EIfzZpU4fMWu_pEF_lu9GS7J17Yu3uHpZEP8zfgyjDBDa9t-KeFiZL1EbYHplmrSmAglnKYSu8ZlhGN4hGjhsX27LZe9CCTxXANIS1FhnFnNzcIosgBGuz1qRv-6Y1Ie2AWaEmiiuibIQA24nmWwtsDW8kjEzHglY_37N0-BCPPPS4QN8Q",
      "dq":
          "UBj0SLbc-6NnHDFePWUzoLtoYbNp_0YuV28UHTQb2PvNImZPA4RqonqXE-LCkRSpsT4fQDRbm8KIwf1mgx1bu4xE8dxMrqsHPCIi3suupWwBbuRgUBIQuJ2gasMoZVMuEPhGC3M9AVpF_5ehYffOjKAZvdxVE0RIH41hq3SsmnOvDpG3cxzwEZpIi12Vb7qvR9FzBTnGV3kHlYqYuJQqZYbpv0SVzRYjjr7AdlE_pr1qYtA4lmAtwqIWYLL4FD5moEx7-iHI3gwQq5EUAQiEMlxvKsX5L2quxeUUnf4xYl9qDQKM8DN-paZLRd2KXSAWHsFFL_OAldnJ1P06-ksJaQ",
      "qi":
          "qxDj-JqYNTAopsar8wegbGp_o9aq1lSt0a-MG67ZNfxURHO_ZLUvfX8ZOG8KREtc-ZCie6Olx3mtdmuD4wnzOWsTeEmDcRGATCpFBk9aIZX3ljKEem5ib8-mTJWQy_mcx2dK_9qCqdQ8KgMSlKLXlzn_UVAW4g-IDdRLHMqUWykewpaLD46AcWC9C2rhzpCmJbprdx_L9NFcJ-8OeBHVjYk8rpY_7ZtMw1i2J9CZ7y3GvXajuS3SBY9uBiKV1UaOgZG98UDZepqJ7LAJ3GQcbRKaepaNyBXeM_Ri7inWk_ZqjvaEY9u5pUDBxO2tB3rE27X8mSFUi2x4HJqqBA9gpw"
    },
    "publicRawKeyData": null,
    "publicSpkiKeyData":
        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1OlzfQdInFgNUajjmoDabCI3n+9KELvBUo2S5Ii5cjrrDGdDPWR62ZUJHTOeCoRSgphEehhHvXWa/oPDvw/ZSPJc5vmOVtO4OrSEuq+oqL0WNdQgZOAyGT1Xu3yEf7hhq0Yva+mdIMHkfDBrEPYrXdfNqqTU3XxXQS3eiPjRpwpaElBbhl4zuVefs2Uz/SZaVtiBJ5fnF3NXSVS3YJB7SMibZMOrj3F2FnFlflHJncixEfy9PfBraykqbuXLaKSAuvRssXzpzCbh67Bh0Nfpoq/fXi3X1eejHMrgfO7efxCcxScfEMJXcYsjsYKHsTrRiGeyqC7aMCe20o/opnveNSCFeCazRNMOInCmTDEzGocUIc0ZFqveanOpgfYfWUPhYxkZnaBDcb0B81/mM9cBrnvCCdSCxo5Oeuw6mGCKQbLKcUKSOnTz2hW6totX1o+K4cvqOFm1FilkC0SOz9oIlW3Ldg4k865USjVFefPYv/6wl6giielNUhvGJ3BLA5N9tCCmjop1ydjRh8mq0MErqXaA0lOVAoRqbp7YIpU/hrMpmqamNDPFjOVIaExbhzZdiGpBkP+vH1pv3Ez4hvwJdaLy3LVphnNEMO4NEmwqzjx2kF98uYB5sjvkujGjeDRaC3HO3m4+oYOZLOkYuoHwf9nYsGOPdZaZTpFB92S5IxcCAwEAAQ==",
    "publicJsonWebKeyData": {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS384",
      "n":
          "1OlzfQdInFgNUajjmoDabCI3n-9KELvBUo2S5Ii5cjrrDGdDPWR62ZUJHTOeCoRSgphEehhHvXWa_oPDvw_ZSPJc5vmOVtO4OrSEuq-oqL0WNdQgZOAyGT1Xu3yEf7hhq0Yva-mdIMHkfDBrEPYrXdfNqqTU3XxXQS3eiPjRpwpaElBbhl4zuVefs2Uz_SZaVtiBJ5fnF3NXSVS3YJB7SMibZMOrj3F2FnFlflHJncixEfy9PfBraykqbuXLaKSAuvRssXzpzCbh67Bh0Nfpoq_fXi3X1eejHMrgfO7efxCcxScfEMJXcYsjsYKHsTrRiGeyqC7aMCe20o_opnveNSCFeCazRNMOInCmTDEzGocUIc0ZFqveanOpgfYfWUPhYxkZnaBDcb0B81_mM9cBrnvCCdSCxo5Oeuw6mGCKQbLKcUKSOnTz2hW6totX1o-K4cvqOFm1FilkC0SOz9oIlW3Ldg4k865USjVFefPYv_6wl6giielNUhvGJ3BLA5N9tCCmjop1ydjRh8mq0MErqXaA0lOVAoRqbp7YIpU_hrMpmqamNDPFjOVIaExbhzZdiGpBkP-vH1pv3Ez4hvwJdaLy3LVphnNEMO4NEmwqzjx2kF98uYB5sjvkujGjeDRaC3HO3m4-oYOZLOkYuoHwf9nYsGOPdZaZTpFB92S5Ixc",
      "e": "AQAB"
    },
    "plaintext":
        "bnR1bSBjb21tb2RvCmRpYW0uIE1hdXJpcyBub24gZHVpIG1hdXJpcy4gU2VkIHBoYXJldHJhLCBuaXNp",
    "signature":
        "T4muOwn+u86trgXfbjIz5ObzRfq1Cf1chMoFBux/ruxAffGlIGxV3HbI3B2rL/siiIM7Gg6INX3Qca1kCBLHx6Eo7vqgr6hPINbbDQMcVgqw3q1qzwZaEA9qnYPsEpskFqQ647LDG2YYwT+OHldOHpbXQRHLxjk4mAiqsjvgJV6s9I9m5ZERiPimXg4gTi7Qjmp8Tfn8CXcgVS3K3NRKIANGm/CbfcCzqtzwvQk53dck6FFNDFxYk1XUzLARAtx6i2fxCeqpeCaXeUr4rETyItjUCfFfLLHmbPDGlggrKOiNjj623ZCEm/VvG9YDfBKCd2wUehE3R+D1EGiSDVZ7dEuLd41Au1CVl1quyMoG99dBAb72Ui7s8tBlEgSvBUypb38M1ndurxOEmxODb8A4ZoXSKovm9QgSVymF06Ol9WOZGXxLlPDbAS2enks6zabhUI0zGiXDFozdFa1z7EPIqWyQXsYj/GiZ8YRzgDTa6p+ZPdmnovU9PnXwtg+2sepyEv3zxs9rRtqMwdyxlN+DXRBgF6DeS+Q1DasSUtDQSsx7wvK0flR5XtfqfryGRPa/brfwGJId1piD5hRvoRuaZhhqQDKuBGYJd7FN/fWRFz7qXLb2o96xbvtmHbtwsXrSCwNcdsYodKjYHyOSrPO9IlObQkVf4b0V3zDb8w5+Xhs=",
    "importKeyParams": {"hash": "sha-384"},
    "signVerifyParams": {}
  },
  {
    "name": "4096/384 generated on chrome/linux at 2020-01-14T19:40:58",
    "generateKeyParams": null,
    "privateRawKeyData": null,
    "privatePkcs8KeyData":
        "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",
    "privateJsonWebKeyData": {
      "kty": "RSA",
      "alg": "RS384",
      "d":
          "WfFqSOWdNNFWndeNCM3vQplLedBzDfmGhR6WenkoQVUwifxK3EiWKTWoAufYZvtTiDCIOOCjH09V0Dh-CNiXdViOAlCdSXK5OYofnLUhc4qON9TeqBAn__fg9nlBOGx92XY0hMgfXzFKu4eSRtAbEfirMvryVVDdeAuI2AX3zI1KTZ1tM0ufAiZM--1Ht3l1K6XVOaFoRRe3uh8R5yVpM4M1g3ASt9qTO5nuLnVXMagiUTc_WPA53LDKiOSrL1Z5fazVmxRrU3CTYpIB2BQn1BgEouDoHcQdJZzQHEd976dneBzwffGDzxR9wCpk_Aw6tJNgi0SjB_3BOd01bXei9_pNQkthE_t3jKM_qRqK6W1t2ZhDChS0brmW5HexPVPKy-0m9PnJfC72L8_CaeFD4hClQUxuHC9EYeWiTLjVm9Z22AAQ9Fb0MqvdFEgcMxeyxw-Gwt_n7CKBeW_Y1WrOi198L0YPRlb1LScNQj5NKh-HLJfd5KjJv2A7L3zYWukcE0MgSYyC-hT_4CszByUGvBMd-UOpeHtAH5iK6VRjyFab6fEGq98BJ0dxcUyRWNKfBYAJr_K_m-hTXGOeo--jFf8_JmNgWOPSWjZ5q3MaAODUBEMNnodaObz4rC_t8SJ_nDgunwJo1MTHBEyVFgefoxMnHzzIK1emd6O64RGp0pE",
      "n":
          "2PnxanPxqXZlqye1S9Zs6xhcEzj9gcDjWaJsgjmjnp2N_Yn5Frujjne0eAzYwpr1u8umCmR4WkJ7WHCIwxW9_9ScCZlDuaCuaDIRHs-5-R8CbOebogVL4tzBsA4-t7_n7sZggLoXOyyst1JdyIUSwybmi21P4gbUbSFM761gL_5BXinYv_B-Bg_hHOdHk4f-A0BD14rxsN0mvLw87rO0IhQBdQ972TBJCAyH4tvlfhXhYyf86TOGL3_DB2iWu8hCmsUIQ2nuE2Ra-3sGFCpnTKgA7pJ7yhn6m3t9ByEuXQ6p5UxrHMTizZkgF5jYfiGqsKESZAdo0fTMQO4PnHafk3N5XVO4vYar2C_yc0w7r-jRVxCAdldgh7H3_JbEU_qw4xgEdORjseb4TaovEFwXForxQvOSXx5DHkNTlpy1MEBSp00dgDUjBOUyej722CAXnH-BynlFywCtvcg5bo41CiPuz326ZVxSS-pgnQJguMu4DYHZf_rUZ-IjDdnlQLzlkL7p7hFNHUmlkQcfUZT-7Xs1aC8MasF6adPTAusirWiE8biT89qWhHE9SrESIs7gevrmru2XVqRgHDN_O5Xe_hZcD2DlxVB48McM1LnStGaXnNFRS42ZEe8YNWFNHkeeUnwq8Zy9ToFf8fg8iIzfV_5UdUHnLPuM7zfwy_WzTI8",
      "e": "AQAB",
      "p":
          "7JUU9TpyqSJ9Ue4KfWP1tamx6EfwHwNxCYuikKLnusUGBISMvvyAEpmEorPtntgmLR37hk1K_BwgeK2QLZ-hA9g1EfPVO2iPBalDmrE7XqeSfialSztqr2fPM-PaQAeufIkARr_XTdGmgyHLtN7HQX18Yj4dqtuUGIyG5Q21S5rqXdJGn8FFsgC087FRdJRGy9PARodaVR4OEAKezpk4u1JOGUA52YN3qAkzpmEe6zgFGQ3RO0m1EtlDxbnheLWnH7r8AnOPoo2lZZOvXyEiOYp5BRfUAbjTYMEGjFaNOeKbMi2Bks-yATkmd_O7Ip1HfSRyQEyvtzxn9lrTTo3RqQ",
      "q":
          "6sjpf_EyDIjRHIckvggT-xf5YW62wIYkLhN4tbTSAEahZkiU_4u4H_DY0rCsGq3Yy0qkp0tF-BnE4n8t6nWCdSvXy5BzyOIDXKZu8_Mviq5A2G7J8Ctzhv-d2Q4cfikUBLqtUTUuqdbNJfBRz6DxHAC55bJj-U_7HFPq0FGzLQB3jbJWw5bOH0z8nQ262MXuw7ddnoWb_i3Wa54XW1AvI5t5-O-WVL4k7paCIHsyFQSqUl4l2Ick5nIxRVhZQPgsQ4VnNioZ0qOX0F3UKoltqaVVQmu3JNEXTBA3IMfuPElIh908nbkc7tt3FRxY8ArWhCnV-66PP33eutkaoyR_dw",
      "dp":
          "p5F0lbk_S4LtRqGW9nddqr02ELMbZawXXU5054MrJQO2Hm8QDZpk0EfCRUeyD6dDawNoixil-umlKjStAVOmRUXXWQ7ewkRtwPHBu4i653FDdmzC-QVtrC2X-kXx6RZHxVd4RaRNyIWtLgY69bIxabaK6j7a3pDGVZj7VrOd7J4eUDPG6BKJ3elYQZ8fdbYsauRhtNLb7ZvrE_X3K5glMbC7NnFiSCkxEGjsF3WE48_69GLwBtFPGrmeoiblh40KgZP8OXRGkTlIpCi1t2iNiDoHO89Dz7Bsr4Qosi__ubdCe4j11NmdV_Z1w9JzgrHp175_2gE3GE8Fx91O-73BeQ",
      "dq":
          "lv9yFQPlgWQ4wNU1zzXYy-NmUsBmrrlW6X9CYfKSIPVL9kF1-kg8ueYnPJG9jkcCp_QwoxtpO6AvHNBYknLS3VK-LcCQhsC9EshDkYd0qwdY0xmlrF31pfwd46wMrSL0Kfp5X0IJ6dcpB15g71z91FmvNUgevggvYs-htCrnRmkHes0Yuh_yHvVffg6HfcUGwz7Z6graAYYvYfVB5ktSld73eh90mrnTfNK1i_hPhG8Er4a3ZmO8Wq1UfNnORVeW-DIC6DX5d5wZFjxSKK1MJxAbHmWyWu5SwmunWODcmk8zY5Xo1zNnpULmemBJ3s_JmSRi58Qjgt0L8zWPyR6_Dw",
      "qi":
          "Od8PJDDqLL-HFfsnCn5Ih91_AQ_1BKjHTm9MA0z6dG_tAccHyNV5ECpBWJsDa0Nk9sNsYHCH_vfcKpDUM9GMKqI02Q4lhl5QCJo8-TCJchVZhWYkyRDc3lPVq7NGijgy4mrhPEaWlH-1hfrj09fPT2lYusaJlqRKONZFscgsUSId34w3IVkrS9DCs7w4_pMPkrI94uXG-px1vXc9-wh8xRYnvrvJgZd2yk1R6OeVPmRNVIW14bBeIs8ew2yv_8PvKLWsL63eT3Y8EkqFNlCgNcuW_96ctZeoqBN1pY68sdNx6ZYkXhTpgfbGiqSvCzOxd3KaqR08MzhhSO0AdKe7pw"
    },
    "publicRawKeyData": null,
    "publicSpkiKeyData":
        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2PnxanPxqXZlqye1S9Zs6xhcEzj9gcDjWaJsgjmjnp2N/Yn5Frujjne0eAzYwpr1u8umCmR4WkJ7WHCIwxW9/9ScCZlDuaCuaDIRHs+5+R8CbOebogVL4tzBsA4+t7/n7sZggLoXOyyst1JdyIUSwybmi21P4gbUbSFM761gL/5BXinYv/B+Bg/hHOdHk4f+A0BD14rxsN0mvLw87rO0IhQBdQ972TBJCAyH4tvlfhXhYyf86TOGL3/DB2iWu8hCmsUIQ2nuE2Ra+3sGFCpnTKgA7pJ7yhn6m3t9ByEuXQ6p5UxrHMTizZkgF5jYfiGqsKESZAdo0fTMQO4PnHafk3N5XVO4vYar2C/yc0w7r+jRVxCAdldgh7H3/JbEU/qw4xgEdORjseb4TaovEFwXForxQvOSXx5DHkNTlpy1MEBSp00dgDUjBOUyej722CAXnH+BynlFywCtvcg5bo41CiPuz326ZVxSS+pgnQJguMu4DYHZf/rUZ+IjDdnlQLzlkL7p7hFNHUmlkQcfUZT+7Xs1aC8MasF6adPTAusirWiE8biT89qWhHE9SrESIs7gevrmru2XVqRgHDN/O5Xe/hZcD2DlxVB48McM1LnStGaXnNFRS42ZEe8YNWFNHkeeUnwq8Zy9ToFf8fg8iIzfV/5UdUHnLPuM7zfwy/WzTI8CAwEAAQ==",
    "publicJsonWebKeyData": {
      "kty": "RSA",
      "alg": "RS384",
      "n":
          "2PnxanPxqXZlqye1S9Zs6xhcEzj9gcDjWaJsgjmjnp2N_Yn5Frujjne0eAzYwpr1u8umCmR4WkJ7WHCIwxW9_9ScCZlDuaCuaDIRHs-5-R8CbOebogVL4tzBsA4-t7_n7sZggLoXOyyst1JdyIUSwybmi21P4gbUbSFM761gL_5BXinYv_B-Bg_hHOdHk4f-A0BD14rxsN0mvLw87rO0IhQBdQ972TBJCAyH4tvlfhXhYyf86TOGL3_DB2iWu8hCmsUIQ2nuE2Ra-3sGFCpnTKgA7pJ7yhn6m3t9ByEuXQ6p5UxrHMTizZkgF5jYfiGqsKESZAdo0fTMQO4PnHafk3N5XVO4vYar2C_yc0w7r-jRVxCAdldgh7H3_JbEU_qw4xgEdORjseb4TaovEFwXForxQvOSXx5DHkNTlpy1MEBSp00dgDUjBOUyej722CAXnH-BynlFywCtvcg5bo41CiPuz326ZVxSS-pgnQJguMu4DYHZf_rUZ-IjDdnlQLzlkL7p7hFNHUmlkQcfUZT-7Xs1aC8MasF6adPTAusirWiE8biT89qWhHE9SrESIs7gevrmru2XVqRgHDN_O5Xe_hZcD2DlxVB48McM1LnStGaXnNFRS42ZEe8YNWFNHkeeUnwq8Zy9ToFf8fg8iIzfV_5UdUHnLPuM7zfwy_WzTI8",
      "e": "AQAB"
    },
    "plaintext": "IGxhb3JlZXQ=",
    "signature":
        "kFyt16Lv6dw1oEwi5McDjHP3fImkTCT76IzAKSQa8Xft4Ga0Ou84MWYWRt5TQeCHf3AWEVsEe+92CeNcZuEP3A9e1vpPptlQAk9fdZjWrTyzRRvEC6WSUcqFX6dg4A+JrEXfB9ZvtyHBeQqVUbA3YGbcwNzy6NHFDr/m1DSm6tgPIEDeD1qIT5k1RFJXwy1ueanpw2gI+2V3gZJiHXC5deaELbQCSCyEuMn1B/kzh1DxU5CDlqZnjR8+DIk+AoLXqEnwx8D/JCyTxhYMhrpz/yutEQS9tzDw4RV7qUHQTx34hEQJSNHMxEiI6Dv8xXYeGSVIcFvVPjHTVgiRydpx352SIJe9kg2pnnn/mAKPPD+5EyIBsa56oHfM7t7IwJpNMozwzMxM1qa9C0um4lqRzK+xikkZYKjvHGgPLdoiRHCkp7X6tIemjN9RVm3n2w4bfG+6P9DRux+hzAENtwEYVPyGw6n6TZOpvK294ro11EoZx8hudTLLet52id3rFYvP3Hxz7pBKIpKCq1eqErn6a4hlL6Ob1MdeRSOVMAS8drZtLgPjYe9WN5YKsboqsiIgLsY7x9zBFGi7evyQThQCAk94/jfKNv2pYBRH0PQlMMqtBPMmkdd0wiEzFZJ8AqSNSxZO4rmWhrRtssPwrzHipDPthnOqBQ79lwN+MUqilAk=",
    "importKeyParams": {"hash": "sha-384"},
    "signVerifyParams": {}
  },
  {
    "name": "4096/384 generated on firefox/linux at 2020-01-14T19:41:07",
    "generateKeyParams": null,
    "privateRawKeyData": null,
    "privatePkcs8KeyData":
        "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",
    "privateJsonWebKeyData": {
      "kty": "RSA",
      "alg": "RS384",
      "d":
          "Lv4zD8LgPMTv_Xjl6JU9PDr4G82yj4-jfnIvK9V84csIT1FaT1G67YwPVjpiT-g6FtiqR1ohE50rmmxdUO3C3ifG9tQPEXeOmhzkPRljftb1vvBthNC47quc4FSHinRRJl-OCaQYfpAYcB73sFerqt-lR_YFP8cN5sHeqJX6NT8VPTDypG4ASr3L6v8H7S8qsZ2LzVaC4x84Gxt-dspyUuuCBmeIZ8NnetV1rtEjQdz-KJDfc5hvL6oNYOYwRCpFOtKwO36gctOC89cUoyLDR4urwQdeRyarfiLOcUfJAhb_XmXdWjoaUwDlOp_wf3m2UNOohjEKL-Ids3ii1v0lnfGMHwLBhNky-EZFdp5GrxNJtUCC2Lrq501-Eoo3sAMw1opMVHOflbb8EJSzRAPVFMny6jvE_sZF3fl7SDClp7uco0t-tRh6xJLwzkNdV5z7XI2571YXQxapJQAmKv4tZDFqqo7ywZkhcqd6z5oheeBg-ofh85Dkn10grgGPK4FkiCwbXPPETCMoekZmVYGyQRNtAEj8JyW4uomneuwmA2uliJ6pkUJ-NEWjIiOcSWt7NI12jxG43s8SJYIHFeB52_oNZFDJ4oK5qceYMfvZq3_ETeMWv-9pQ-DpWhqR-FjVOiASeyAhZFqEj8j-D_C3f5v_QFmHkcOT1zWe7o16mMU",
      "n":
          "p-5wvu31QrgddYaXJ3T-jD-S4TmNAoW6OG53OTvfdzOAwVOdp5k8252oWxeXVwVE-qhDSEcyU0vkDGxKMiQ_n6oVmlnvnpptwSnqqBox_XrTb0av_2rGgGp49BPnVZZW2SQjccnFerbctTTooUzy5KbeChUjA2AU9rUGfYOC455ZmzSBFWarzZTf1Cd9H7ypDb71CJws_54b77fh0yJ8ttwak5wQtoZCr2g-3_uP5VBiA3ZWUI4yWe1Eh97LQtX-_wrsc_uduK7nBn-T0jv1nm0im2SEAMRa_uFnMVO8mr-3731li6wrmGLG1qKRSlrwiLaoW1A01WFvQQS6vMtj553cQuLRtOKqTtNgjqbn3NYSH18euuJp4XLqQiOFwGH9kzyFye7oNXOAchTc-UJ8Af5wwopPkBH4CDBo0PSqPCUd1VvOcggDQEgeoXvH55YZYR7lw7tkya-pNvnJUdDKFpqO6YIShtCTf18jTuxsyB7TgkHOSmtJX3rNEGvD8Fzya5fDxuwgv06Sfa410a0_AF4VuMoJzuRx_hGT27jumUyUVcphjICGg5bexokLgv3K1xNhr6k9HVjoGXZtO8y_BA9K-PoEqRStEbagSNmz5BurCluX2QoDTGjFfLELUef4XmovGkunIAm71ICJI3BkdKJVsP3vLFlEDicNE6jPYDs",
      "e": "AQAB",
      "p":
          "z5wEpNVesSZxR-0DqzoqELDf3gy7K3YDwms8ln6t6GWhtSuaZrG1pj3tT0Jg3JHLBCcuIxYjTjmnrQwqjuGkRLSjYh_UbSL9bw5JismiCEYyzIf9iunhcd2yqJrrfnoUL56zY60A5FAouxiWRHGAIPGvpffFwuIQZdColVYrXt8r7LT5Rd7nmB52xxGEYmkA_juaJ7SEU3nNbcCla5DUfx-VASa2PfcU2prlFGMe6QFJIcjthAHRy8JLlUiJd3pM4t90LNAFpuN0tZCsZalO_9CMUA6u0pX9xOOuV10qgIUIVVta3NyPaG8jo05w2hkj-7yTINWLSVT8N8V8v6ynpQ",
      "q":
          "zxLZDGrFemBXHBrCM4uCCm5JAAvjc3rt-yEgXKnoMCTHa2-sBopxjkQmotWVMXLpuLSZsOrXpsbhq5vjedZ2kRyqp85O403L0vcoo54LyZHNwnFbkhRj5dKOkNwNzZXnVw5HgMSP2zRe17mwQrx8oD2XDEGsuqjCQPL0G5ChjMNRo23D4iM30hVWYT04TfysiiAn3HWFR4Mly6SGfpmxi0GlSor4JsaIIst-syOXlgDk62eEjDUjiCo6ZNLe4daxGkSqd57cnDEOU4KDWPV29VfwcKjRBEH3tVk0Ig2JWYoXBIWId8fUSIktfu6J3zdwn7C8wR7cElVWE2dGHFBiXw",
      "dp":
          "lkgJ1Iffk7yQI9Cd50SjTpG6e7IbispSzllx8j6hBKkM9WgqzEu3gi8xqT4Tf5bJrqft7dgIloeFqO41oFgV4OYhntYLnzTE368n7R8n-3VVMFkAX54NY69ntETwUw1rr0zh7jU9gAfGdCjIHaNLbI2G6E0DCp8533m7jt5hZruFwEMAbmN8odDrig5UFiiMX3wlirhRUVvKKLhbBhJAwATMh5jOMuy4W8XkLW3S4jfcCGi6BeSLSUPMErP_Tk1pepDmN8odTUE5KnUfVjfIx8TezNTUF_wbRnrJqNP4ADBMZ_1JOLcv2BkbYwtVBYtNUNygZBQwT1UFfhmmw9jnQQ",
      "dq":
          "gTeBuf3mvTbhJOiNxxyHSXsIkr7YcHeFifBiAXEFMwXAa4qEDpDVy7E7auFc-D59GoWYYo4phCkXKb9dc-ogku0QkSZsk-s4Ba217mPxdxdFDtEuEzomHIQH8t1ev6uLcQe4FuKR4ngLtxJoqzxziIrmdv-EifZFQcJaEdlu9ifsCc-1LKhNbQtjm8pYGFJUWN04AppTUQzFyQ4h316JLB0KyDlwIMJCsXPK3H6ZWUG1mDBAxj1irtWrGr971fHjEkFHHt5DTDRQfEw1Ko4CbZcysxqlU8LWkJPZtGY-D2HcezXYsuY_0gPIIC06W9B8tynSn7BiJA6cZ_9KAOEogQ",
      "qi":
          "s5qdVsBSS-VujsLahOxAjq5ET0AgWibOiOYg78wxSDv7lcCoPUaPUWfuvcoDzD_6luRmEABIYUp2qxm6wsjCNQo5JEetClw2PaI-jTEvc4K67r07Sd2h0FNtcQnN4-DSZAdoY4Y59S1k2AXFvxO6LzGDvN_YSkpAuBsKXojYW5GcCiO542u_0C6nPJEWbwcbFhc6U2iRKVISnd7bQ2jlXfW62VesPmOnxaq9vrw31pPzTREN1mQB2chWOtpTb7ZjVmfiYCnxDJ52zeoTdNP5rc-9AqxCXhMhRZbZqNyR_peKSv2Xfnf_pIvoIy8j7bYJ-8S9YeJGqVimfNvJ_4qkUQ"
    },
    "publicRawKeyData": null,
    "publicSpkiKeyData":
        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAp+5wvu31QrgddYaXJ3T+jD+S4TmNAoW6OG53OTvfdzOAwVOdp5k8252oWxeXVwVE+qhDSEcyU0vkDGxKMiQ/n6oVmlnvnpptwSnqqBox/XrTb0av/2rGgGp49BPnVZZW2SQjccnFerbctTTooUzy5KbeChUjA2AU9rUGfYOC455ZmzSBFWarzZTf1Cd9H7ypDb71CJws/54b77fh0yJ8ttwak5wQtoZCr2g+3/uP5VBiA3ZWUI4yWe1Eh97LQtX+/wrsc/uduK7nBn+T0jv1nm0im2SEAMRa/uFnMVO8mr+3731li6wrmGLG1qKRSlrwiLaoW1A01WFvQQS6vMtj553cQuLRtOKqTtNgjqbn3NYSH18euuJp4XLqQiOFwGH9kzyFye7oNXOAchTc+UJ8Af5wwopPkBH4CDBo0PSqPCUd1VvOcggDQEgeoXvH55YZYR7lw7tkya+pNvnJUdDKFpqO6YIShtCTf18jTuxsyB7TgkHOSmtJX3rNEGvD8Fzya5fDxuwgv06Sfa410a0/AF4VuMoJzuRx/hGT27jumUyUVcphjICGg5bexokLgv3K1xNhr6k9HVjoGXZtO8y/BA9K+PoEqRStEbagSNmz5BurCluX2QoDTGjFfLELUef4XmovGkunIAm71ICJI3BkdKJVsP3vLFlEDicNE6jPYDsCAwEAAQ==",
    "publicJsonWebKeyData": {
      "kty": "RSA",
      "alg": "RS384",
      "n":
          "p-5wvu31QrgddYaXJ3T-jD-S4TmNAoW6OG53OTvfdzOAwVOdp5k8252oWxeXVwVE-qhDSEcyU0vkDGxKMiQ_n6oVmlnvnpptwSnqqBox_XrTb0av_2rGgGp49BPnVZZW2SQjccnFerbctTTooUzy5KbeChUjA2AU9rUGfYOC455ZmzSBFWarzZTf1Cd9H7ypDb71CJws_54b77fh0yJ8ttwak5wQtoZCr2g-3_uP5VBiA3ZWUI4yWe1Eh97LQtX-_wrsc_uduK7nBn-T0jv1nm0im2SEAMRa_uFnMVO8mr-3731li6wrmGLG1qKRSlrwiLaoW1A01WFvQQS6vMtj553cQuLRtOKqTtNgjqbn3NYSH18euuJp4XLqQiOFwGH9kzyFye7oNXOAchTc-UJ8Af5wwopPkBH4CDBo0PSqPCUd1VvOcggDQEgeoXvH55YZYR7lw7tkya-pNvnJUdDKFpqO6YIShtCTf18jTuxsyB7TgkHOSmtJX3rNEGvD8Fzya5fDxuwgv06Sfa410a0_AF4VuMoJzuRx_hGT27jumUyUVcphjICGg5bexokLgv3K1xNhr6k9HVjoGXZtO8y_BA9K-PoEqRStEbagSNmz5BurCluX2QoDTGjFfLELUef4XmovGkunIAm71ICJI3BkdKJVsP3vLFlEDicNE6jPYDs",
      "e": "AQAB"
    },
    "plaintext":
        "cmRpZXQuIFByb2luIGluIGxhY2luaWEgZXguIFNlZCBmZXVnaWF0IGVnZXN0YXMgbHVjdHVzLiBDcmE=",
    "signature":
        "XFVSFR/YcVNBwVuW6le0cV1nmJjC/2xYHtxghI9HiqoJFvM/i6GhD7RJrrUey6qJlb1uRJyJWsF3UMpmjmtBq7T0MErhGMXOeI5cX3jnFsk2JHqL10QwCkRnH+QFyTJ6bH3jC+f03T7enCIiNax4QDzCS/VHyrYcoqzkUSBv1R8pd71cQvnYBJUS3CymO0rUb0Z9azI1N4mKgMGRUIJy/E6UQdO75z/qQfNVOqFaVHscJdUx9KdNnhPtl1K7kYtoH2LE7b+mqK+YIYKsbGycHl644I12pWhOtnsltfffcLBexDQbow/Fu9STtcuKW4b3w/lQZOyacGZT+Z3TDE9UzXmXi/7z6uU3WOK71Vc/reY4hb7zp2J06K2XNKPoeSFP1fn6736qaRUusdWKWbsTHC4bpfHEszY2r8LINZok6VY7zBV8JvoanpAlE7Mjns7jSTnSM8xgpsD3pcasnMntggEOifNtXjYCaRzNGH2urpVh+MfzS2Kk2c43+0Wd03NwUyeVCZVOPjT4OSYvhgu3LQddXajRDVQ7XL8jqk5maXGGMeKWTPVpcCFlnvEfsiYEMsOvCaIVHq7Z20sloQnWBpkIJr8LX+/0NBSt0t4t2WMmg9mBAKK2mTfap2Ean8nSi7UleuQtmxBKj7aVKrJoeWikWgrjK2mLDACsmOUxmFU=",
    "importKeyParams": {"hash": "sha-384"},
    "signVerifyParams": {}
  },
];
