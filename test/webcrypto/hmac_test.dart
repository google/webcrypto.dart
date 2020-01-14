import 'package:webcrypto/webcrypto.dart';
import '../utils.dart';
import '../testrunner.dart';

class _KeyPair<S, T> implements KeyPair<S, T> {
  final S privateKey;
  final T publicKey;
  _KeyPair({this.privateKey, this.publicKey});
}

final runner = TestRunner<HmacSecretKey, HmacSecretKey>(
  importPrivateRawKey: (keyData, keyImportParams) =>
      HmacSecretKey.importRawKey(keyData, hashFromJson(keyImportParams)),
  exportPrivateRawKey: (key) => key.exportRawKey(),
  importPrivatePkcs8Key: null, // not supported
  exportPrivatePkcs8Key: null,
  // Not implemented (in FFI) yet
  // importPrivateJsonWebKey: (jsonWebKeyData, keyImportParams) =>
  //     HmacSecretKey.importJsonWebKey(
  //         jsonWebKeyData, hashFromJson(keyImportParams)),
  // exportPrivateJsonWebKey: (key) => key.exportJsonWebKey(),
  importPublicRawKey: (keyData, keyImportParams) =>
      HmacSecretKey.importRawKey(keyData, hashFromJson(keyImportParams)),
  exportPublicRawKey: (key) => key.exportRawKey(),
  importPublicSpkiKey: null, // not supported
  exportPublicSpkiKey: null,
  // Not implemented (in FFI) yet
  // importPublicJsonWebKey: (jsonWebKeyData, keyImportParams) =>
  //     HmacSecretKey.importJsonWebKey(
  //         jsonWebKeyData, hashFromJson(keyImportParams)),
  // exportPublicJsonWebKey: (key) => key.exportJsonWebKey(),
  generateKeyPair: (generateKeyPairParams) async {
    final key = await HmacSecretKey.generateKey(
      hashFromJson(generateKeyPairParams),
      length: generateKeyPairParams['length'] ?? null,
    );
    return _KeyPair(privateKey: key, publicKey: key);
  },
  signBytes: (key, data, signParams) => key.signBytes(data),
  signStream: (key, data, signParams) => key.signStream(data),
  verifyBytes: (key, signature, data, verifyParams) =>
      key.verifyBytes(signature, data),
  verifyStream: (key, signature, data, verifyParams) =>
      key.verifyStream(signature, data),
);

void main() {
  test('generate HMAC test case', () async {
    await runner.generate(
      generateKeyParams: {'hash': hashToJson(Hash.sha256), 'length': 37},
      importKeyParams: {'hash': hashToJson(Hash.sha256), 'length': 37},
      signVerifyParams: {},
      maxPlaintext: 80,
    );
  });

  runner.runAll([
    {
      "name": "use generated key",
      "generateKeyParams": {"hash": "sha-256"},
      "plaintext":
          "cyBpbiBhbnRlIG5vbiwgc29kYWxlcyBzY2VsZXJpc3F1ZSBxdWFtLgpBbGlxdWFtIHZpdGFlIHNhZ2l0dGlzIGZlbGlzLiBPcmM=",
      "importKeyParams": {"hash": "sha-256"},
      "signVerifyParams": {}
    },
    {
      "name": "raw key generated on chrome/linux at 2019-12-27T11:07:32",
      "privateRawKeyData":
          "I6q4wElrxDYdHj/aTCGfWmlLHDQ06UBypojTPIHhe5iM8QXvLdThLnug4M9T0TCOXCNooC5zhVIc7/8RzdOGMQ==",
      "publicRawKeyData":
          "I6q4wElrxDYdHj/aTCGfWmlLHDQ06UBypojTPIHhe5iM8QXvLdThLnug4M9T0TCOXCNooC5zhVIc7/8RzdOGMQ==",
      "plaintext":
          "bGl0IGFjIHNvbGxpY2l0dWRpbiB0aW5jaWR1bnQsIHVybmEgdGVsbHVzCnZlaGljdWxhIG8=",
      "signature": "wM/PDNUt7JQrdUET+XSml9sRMZBcImljaeRJ3yZK+CQ=",
      "importKeyParams": {"hash": "sha-256"},
      "signVerifyParams": {}
    },
    {
      "name": "raw key generated on ffi/boringssl at 2019-12-23T16:23:50",
      "privateRawKeyData": "CVT8yOBuzRX0OJK45lhgTh3yH/C0xzwtx6mY1iOmlEg=",
      "publicRawKeyData": "CVT8yOBuzRX0OJK45lhgTh3yH/C0xzwtx6mY1iOmlEg=",
      "plaintext":
          "cyBpbiBhbnRlIG5vbiwgc29kYWxlcyBzY2VsZXJpc3F1ZSBxdWFtLgpBbGlxdWFtIHZpdGFlIHNhZ2l0dGlzIGZlbGlzLiBPcmM=",
      "signature": "JQSrWn+xcshvRo3fVxA8Pkvi+DOKskxCr/01RXlUEPE=",
      "importKeyParams": {"hash": "sha-256"},
      "signVerifyParams": {}
    },
    {
      "name": "raw key generated on firefox/linux at 2019-12-27T11:26:21",
      "privateRawKeyData":
          "rBmoXgAfMnwpzGJcy6i0xhEoiwzpZjLVXo3xsxOME12tmJSIHWy5LPWlvt3adGFpJhOYt4SgRelz36lQ1pOpkQ==",
      "publicRawKeyData":
          "rBmoXgAfMnwpzGJcy6i0xhEoiwzpZjLVXo3xsxOME12tmJSIHWy5LPWlvt3adGFpJhOYt4SgRelz36lQ1pOpkQ==",
      "plaintext": "aXMgaWQuIENyYXMgdGVtcHVzIHNvZGFsZXM=",
      "signature": "/rpu3udbnZPemRiygmyYTsBsXFtYrIINbp9jIscbuhw=",
      "importKeyParams": {"hash": "sha-256"},
      "signVerifyParams": {}
    },
    {
      "name": "use generated key with length 37",
      "generateKeyParams": {"hash": "sha-256", "length": 37},
      "plaintext":
          "bmVuYXRpcywgbWkgcXVpcyBzYWdpdHRpcyB0cmlzdGlxdWUsIG1hc3NhIHZlbGl0IHJob25jdXMKZXgsIHF1aXMgcnV0cnVtIGVyYXQ=",
      "importKeyParams": {"hash": "sha-256", "length": 37},
      "signVerifyParams": {}
    },
    {
      "name":
          "raw key length 37 generated on ffi/boringssl at 2019-12-27T11:34:31",
      "privateRawKeyData": "mnKq0+g=",
      "publicRawKeyData": "mnKq0+g=",
      "plaintext":
          "bmVuYXRpcywgbWkgcXVpcyBzYWdpdHRpcyB0cmlzdGlxdWUsIG1hc3NhIHZlbGl0IHJob25jdXMKZXgsIHF1aXMgcnV0cnVtIGVyYXQ=",
      "signature": "Kt13MwmnE7e0KnvrpQjeEYSfLQDTBJdUOxWm4jlECqU=",
      "importKeyParams": {"hash": "sha-256", "length": 37},
      "signVerifyParams": {}
    },
    {
      "name":
          "raw key length 37 generated on chrome/linux at 2019-12-27T11:39:51",
      "privateRawKeyData": "F5emtng=",
      "publicRawKeyData": "F5emtng=",
      "plaintext":
          "ZXNxdWUgaGFiaXRhbnQgbW9yYmkgdHJpc3RpcXVlIHNlbmVjdHVzIGV0IG5ldHVzIGV0IG1hbGVzdWFkYSBmYW0=",
      "signature": "M1ms4yIHz6hDLLqYcnqGds7rJ1CQXIWDEOxcCYYArj8=",
      "importKeyParams": {"hash": "sha-256", "length": 37},
      "signVerifyParams": {}
    },
    {
      "name":
          "raw key length 37 generated on firefox/linux at 2019-12-27T11:40:39",
      "privateRawKeyData": "nfClRQ==",
      "publicRawKeyData": "nfClRQ==",
      "plaintext": "LgpBbGlxdWFtIHZpdGFlIHNhZ2l0dA==",
      "signature": "FcF2TSDp4dRXCK8jVqnnDwKuHd52yN2YKYBiOiZhvzQ=",
      "importKeyParams": {"hash": "sha-256", "length": 37},
      "signVerifyParams": {}
    },
  ]);
}
