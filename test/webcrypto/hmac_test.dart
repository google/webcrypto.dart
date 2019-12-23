import 'dart:convert';
import 'package:webcrypto/webcrypto.dart';
import '../utils.dart';
import '../testrunner.dart';
import 'package:test/test.dart';

class _KeyPair<S, T> implements KeyPair<S, T> {
  final S privateKey;
  final T publicKey;
  _KeyPair({this.privateKey, this.publicKey});
}

final runner = AsymmetricTestRunner<HmacSecretKey, HmacSecretKey>(
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
  test('generate test case', () async {
    final c = await runner.generate(
      generateKeyParams: {'hash': hashToJson(Hash.sha256)},
      importKeyParams: {'hash': hashToJson(Hash.sha256)},
      signVerifyParams: {},
      maxPlaintext: 80,
    );
    print(JsonEncoder.withIndent('  ').convert(c.toJson()));
  });

  group('test testcase', () {
    runner.run(AsymmetricTestCase.fromJson(json.decode(
      '''
      {
        "name": "Test raw keys (Generated at 2019-12-23T16:23:50.585583)",
        "privateRawKeyData": "CVT8yOBuzRX0OJK45lhgTh3yH/C0xzwtx6mY1iOmlEg=",
        "privatePkcs8KeyData": null,
        "privateJsonWebKeyData": null,
        "publicRawKeyData": "CVT8yOBuzRX0OJK45lhgTh3yH/C0xzwtx6mY1iOmlEg=",
        "publicSpkiKeyData": null,
        "publicJsonWebKeyData": null,
        "plaintext": "cyBpbiBhbnRlIG5vbiwgc29kYWxlcyBzY2VsZXJpc3F1ZSBxdWFtLgpBbGlxdWFtIHZpdGFlIHNhZ2l0dGlzIGZlbGlzLiBPcmM=",
        "signature": "JQSrWn+xcshvRo3fVxA8Pkvi+DOKskxCr/01RXlUEPE=",
        "importKeyParams": {
          "hash": "sha-256"
        },
        "signVerifyParams": {}
      }
      ''',
    )));

    runner.run(AsymmetricTestCase.fromJson(json.decode(
      '''
      {
        "name": "Test generate key (Generated at 2019-12-23T16:23:50.585583)",
        "generateKeyParams": {
          "hash": "sha-256"
        },
        "privateRawKeyData": null,
        "privatePkcs8KeyData": null,
        "privateJsonWebKeyData": null,
        "publicRawKeyData": null,
        "publicSpkiKeyData": null,
        "publicJsonWebKeyData": null,
        "plaintext": "cyBpbiBhbnRlIG5vbiwgc29kYWxlcyBzY2VsZXJpc3F1ZSBxdWFtLgpBbGlxdWFtIHZpdGFlIHNhZ2l0dGlzIGZlbGlzLiBPcmM=",
        "signature": null,
        "importKeyParams": {
          "hash": "sha-256"
        },
        "signVerifyParams": {}
      }
      ''',
    )));
  });
}
