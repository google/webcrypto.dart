@TestOn('browser')
@Tags(['experimental'])
library;

import 'dart:convert';
import 'dart:js_interop';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webcrypto/src/crypto_subtle.dart' as subtle;
import 'package:webcrypto/webcrypto.dart';

extension type JSSubtleCryptoWrap(subtle.JSSubtleCrypto _) implements JSObject {
  external JSPromise<JSArrayBuffer> wrapKey(
    String format,
    subtle.JSCryptoKey key,
    subtle.JSCryptoKey wrappingKey,
    JSAny algorithm,
  );

  external JSPromise<subtle.JSCryptoKey> unwrapKey(
    String format,
    JSTypedArray wrappedKey,
    subtle.JSCryptoKey unwrappingKey,
    JSAny unwrapAlgorithm,
    JSAny unwrappedKeyAlgorithm,
    bool extractable,
    JSArray<JSString> keyUsages,
  );
}

void main() {
  final wrap = JSSubtleCryptoWrap(subtle.window.crypto.subtle);

  final aesKeyBytes = Uint8List.fromList(List<int>.generate(16, (i) => i + 1));
  final iv16 = Uint8List.fromList(List<int>.generate(16, (i) => 0x10 + i));
  final iv = Uint8List.fromList(List<int>.generate(12, (i) => 0x20 + i));
  final counter = Uint8List.fromList(List<int>.generate(16, (i) => 0x30 + i));
  final additionalData = Uint8List.fromList(
    List<int>.generate(8, (i) => 0x40 + i),
  );
  final hmacKeyBytes = Uint8List.fromList(
    List<int>.generate(32, (i) => 0x80 + i),
  );
  final rsaAlgorithm = subtle.Algorithm(
    name: 'RSA-OAEP',
    hash: 'SHA-256',
    modulusLength: 2048,
    publicExponent: Uint8List.fromList([0x01, 0x00, 0x01]),
  );
  final aesGcmAlgorithm = subtle.Algorithm(
    name: 'AES-GCM',
    iv: iv,
    additionalData: additionalData,
    tagLength: 128,
  );

  late subtle.JSCryptoKey jsAesWrappingKey;
  late subtle.JSCryptoKey jsAesCbcWrappingKey;
  late subtle.JSCryptoKey jsAesCtrWrappingKey;
  late subtle.JSCryptoKey jsHmacKey;
  late subtle.JSCryptoKeyPair jsRsaPair;
  late AesGcmSecretKey packageAesWrappingKey;
  late AesCbcSecretKey packageAesCbcWrappingKey;
  late AesCtrSecretKey packageAesCtrWrappingKey;
  late HmacSecretKey packageHmacKey;
  late RsaOaepPublicKey packageRsaPublicKey;
  late RsaOaepPrivateKey packageRsaPrivateKey;
  late Uint8List rsaSpkiBytes;
  late Uint8List rsaPkcs8Bytes;

  setUpAll(() async {
    jsAesWrappingKey = await subtle.importKey(
      'raw',
      aesKeyBytes,
      const subtle.Algorithm(name: 'AES-GCM', length: 128),
      true,
      ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
    );
    jsAesCbcWrappingKey = await subtle.importKey(
      'raw',
      aesKeyBytes,
      const subtle.Algorithm(name: 'AES-CBC', length: 128),
      true,
      ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
    );
    jsAesCtrWrappingKey = await subtle.importKey(
      'raw',
      aesKeyBytes,
      const subtle.Algorithm(name: 'AES-CTR', length: 128),
      true,
      ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
    );
    jsHmacKey = await subtle.importKey(
      'raw',
      hmacKeyBytes,
      const subtle.Algorithm(name: 'HMAC', hash: 'SHA-256'),
      true,
      ['sign', 'verify'],
    );
    jsRsaPair = await subtle.generateKeyPair(rsaAlgorithm, true, [
      'wrapKey',
      'unwrapKey',
    ]);

    packageAesWrappingKey = await AesGcmSecretKey.importRawKey(aesKeyBytes);
    packageAesCbcWrappingKey = await AesCbcSecretKey.importRawKey(aesKeyBytes);
    packageAesCtrWrappingKey = await AesCtrSecretKey.importRawKey(aesKeyBytes);
    packageHmacKey = await HmacSecretKey.importRawKey(
      hmacKeyBytes,
      Hash.sha256,
    );

    rsaSpkiBytes = (await subtle.exportKey(
      'spki',
      jsRsaPair.publicKey,
    )).asUint8List();
    rsaPkcs8Bytes = (await subtle.exportKey(
      'pkcs8',
      jsRsaPair.privateKey,
    )).asUint8List();

    packageRsaPublicKey = await RsaOaepPublicKey.importSpkiKey(
      rsaSpkiBytes,
      Hash.sha256,
    );
    packageRsaPrivateKey = await RsaOaepPrivateKey.importPkcs8Key(
      rsaPkcs8Bytes,
      Hash.sha256,
    );
  });

  group('wrapKey equivalence', () {
    test(
      'AES-CBC raw wrapping matches exportRawKey + encryptBytes exactly',
      () async {
        final jsWrapped = await _wrapKey(
          wrap,
          'raw',
          jsHmacKey,
          jsAesCbcWrappingKey,
          subtle.Algorithm(name: 'AES-CBC', iv: iv16),
        );

        final packageWrapped = await packageAesCbcWrappingKey.encryptBytes(
          await packageHmacKey.exportRawKey(),
          iv16,
        );

        expect(jsWrapped, orderedEquals(packageWrapped));

        final jsUnwrapped = await _unwrapKey(
          wrap,
          'raw',
          packageWrapped,
          jsAesCbcWrappingKey,
          subtle.Algorithm(name: 'AES-CBC', iv: iv16),
          const subtle.Algorithm(name: 'HMAC', hash: 'SHA-256'),
          ['sign', 'verify'],
        );
        final jsUnwrappedRaw = (await subtle.exportKey(
          'raw',
          jsUnwrapped,
        )).asUint8List();
        expect(jsUnwrappedRaw, orderedEquals(hmacKeyBytes));

        final packageUnwrappedRaw = await packageAesCbcWrappingKey.decryptBytes(
          jsWrapped,
          iv16,
        );
        expect(packageUnwrappedRaw, orderedEquals(hmacKeyBytes));
      },
    );

    test(
      'AES-CTR raw wrapping matches exportRawKey + encryptBytes exactly',
      () async {
        final ctrAlgorithm = subtle.Algorithm(
          name: 'AES-CTR',
          counter: counter,
          length: 64,
        );
        final jsWrapped = await _wrapKey(
          wrap,
          'raw',
          jsHmacKey,
          jsAesCtrWrappingKey,
          ctrAlgorithm,
        );

        final packageWrapped = await packageAesCtrWrappingKey.encryptBytes(
          await packageHmacKey.exportRawKey(),
          counter,
          64,
        );

        expect(jsWrapped, orderedEquals(packageWrapped));

        final jsUnwrapped = await _unwrapKey(
          wrap,
          'raw',
          packageWrapped,
          jsAesCtrWrappingKey,
          ctrAlgorithm,
          const subtle.Algorithm(name: 'HMAC', hash: 'SHA-256'),
          ['sign', 'verify'],
        );
        final jsUnwrappedRaw = (await subtle.exportKey(
          'raw',
          jsUnwrapped,
        )).asUint8List();
        expect(jsUnwrappedRaw, orderedEquals(hmacKeyBytes));

        final packageUnwrappedRaw = await packageAesCtrWrappingKey.decryptBytes(
          jsWrapped,
          counter,
          64,
        );
        expect(packageUnwrappedRaw, orderedEquals(hmacKeyBytes));
      },
    );

    test(
      'AES-GCM raw wrapping matches exportRawKey + encryptBytes exactly',
      () async {
        final jsWrapped = await _wrapKey(
          wrap,
          'raw',
          jsHmacKey,
          jsAesWrappingKey,
          aesGcmAlgorithm,
        );

        final packageWrapped = await packageAesWrappingKey.encryptBytes(
          await packageHmacKey.exportRawKey(),
          iv,
          additionalData: additionalData,
        );

        expect(jsWrapped, orderedEquals(packageWrapped));

        final jsUnwrapped = await _unwrapKey(
          wrap,
          'raw',
          packageWrapped,
          jsAesWrappingKey,
          aesGcmAlgorithm,
          const subtle.Algorithm(name: 'HMAC', hash: 'SHA-256'),
          ['sign', 'verify'],
        );
        final jsUnwrappedRaw = (await subtle.exportKey(
          'raw',
          jsUnwrapped,
        )).asUint8List();
        expect(jsUnwrappedRaw, orderedEquals(hmacKeyBytes));

        final packageUnwrappedRaw = await packageAesWrappingKey.decryptBytes(
          jsWrapped,
          iv,
          additionalData: additionalData,
        );
        expect(packageUnwrappedRaw, orderedEquals(hmacKeyBytes));
      },
    );

    test(
      'AES-GCM spki wrapping matches exportSpkiKey + encryptBytes exactly',
      () async {
        final jsWrapped = await _wrapKey(
          wrap,
          'spki',
          jsRsaPair.publicKey,
          jsAesWrappingKey,
          aesGcmAlgorithm,
        );

        final packageWrapped = await packageAesWrappingKey.encryptBytes(
          await packageRsaPublicKey.exportSpkiKey(),
          iv,
          additionalData: additionalData,
        );

        expect(jsWrapped, orderedEquals(packageWrapped));

        final jsUnwrapped = await _unwrapKey(
          wrap,
          'spki',
          packageWrapped,
          jsAesWrappingKey,
          aesGcmAlgorithm,
          const subtle.Algorithm(name: 'RSA-OAEP', hash: 'SHA-256'),
          ['encrypt'],
        );
        final jsUnwrappedSpki = (await subtle.exportKey(
          'spki',
          jsUnwrapped,
        )).asUint8List();
        expect(jsUnwrappedSpki, orderedEquals(rsaSpkiBytes));

        final packageUnwrappedSpki = await packageAesWrappingKey.decryptBytes(
          jsWrapped,
          iv,
          additionalData: additionalData,
        );
        expect(packageUnwrappedSpki, orderedEquals(rsaSpkiBytes));
      },
    );

    test(
      'AES-GCM pkcs8 wrapping matches exportPkcs8Key + encryptBytes exactly',
      () async {
        final jsWrapped = await _wrapKey(
          wrap,
          'pkcs8',
          jsRsaPair.privateKey,
          jsAesWrappingKey,
          aesGcmAlgorithm,
        );

        final packageWrapped = await packageAesWrappingKey.encryptBytes(
          await packageRsaPrivateKey.exportPkcs8Key(),
          iv,
          additionalData: additionalData,
        );

        expect(jsWrapped, orderedEquals(packageWrapped));

        final jsUnwrapped = await _unwrapKey(
          wrap,
          'pkcs8',
          packageWrapped,
          jsAesWrappingKey,
          aesGcmAlgorithm,
          const subtle.Algorithm(name: 'RSA-OAEP', hash: 'SHA-256'),
          ['decrypt'],
        );
        final jsUnwrappedPkcs8 = (await subtle.exportKey(
          'pkcs8',
          jsUnwrapped,
        )).asUint8List();
        expect(jsUnwrappedPkcs8, orderedEquals(rsaPkcs8Bytes));

        final packageUnwrappedPkcs8 = await packageAesWrappingKey.decryptBytes(
          jsWrapped,
          iv,
          additionalData: additionalData,
        );
        expect(packageUnwrappedPkcs8, orderedEquals(rsaPkcs8Bytes));
      },
    );

    test(
      'RSA-OAEP raw wrapping is cross-compatible even though ciphertext is randomized',
      () async {
        final wrapParams = subtle.Algorithm(
          name: 'RSA-OAEP',
          label: Uint8List.fromList([1, 2, 3, 4]),
        );

        final jsWrapped = await _wrapKey(
          wrap,
          'raw',
          jsHmacKey,
          jsRsaPair.publicKey,
          wrapParams,
        );
        final packageWrapped = await packageRsaPublicKey.encryptBytes(
          await packageHmacKey.exportRawKey(),
          label: const [1, 2, 3, 4],
        );

        expect(jsWrapped, isNot(orderedEquals(packageWrapped)));

        final packageUnwrappedRaw = await packageRsaPrivateKey.decryptBytes(
          jsWrapped,
          label: const [1, 2, 3, 4],
        );
        expect(packageUnwrappedRaw, orderedEquals(hmacKeyBytes));

        final jsUnwrapped = await _unwrapKey(
          wrap,
          'raw',
          packageWrapped,
          jsRsaPair.privateKey,
          wrapParams,
          const subtle.Algorithm(name: 'HMAC', hash: 'SHA-256'),
          ['sign', 'verify'],
        );
        final jsUnwrappedRaw = (await subtle.exportKey(
          'raw',
          jsUnwrapped,
        )).asUint8List();
        expect(jsUnwrappedRaw, orderedEquals(hmacKeyBytes));
      },
    );

    test(
      'JWK wrapKey carries ext/key_ops metadata that package exportJsonWebKey omits',
      () async {
        final jsWrapped = await _wrapKey(
          wrap,
          'jwk',
          jsHmacKey,
          jsAesWrappingKey,
          aesGcmAlgorithm,
        );

        final packageWrapped = await packageAesWrappingKey.encryptBytes(
          utf8.encode(jsonEncode(await packageHmacKey.exportJsonWebKey())),
          iv,
          additionalData: additionalData,
        );

        expect(jsWrapped, isNot(orderedEquals(packageWrapped)));

        final jsJwk =
            jsonDecode(
                  utf8.decode(
                    await packageAesWrappingKey.decryptBytes(
                      jsWrapped,
                      iv,
                      additionalData: additionalData,
                    ),
                  ),
                )
                as Map<String, dynamic>;
        final packageJwk =
            jsonDecode(
                  utf8.decode(
                    await packageAesWrappingKey.decryptBytes(
                      packageWrapped,
                      iv,
                      additionalData: additionalData,
                    ),
                  ),
                )
                as Map<String, dynamic>;

        expect(jsJwk['ext'], isTrue);
        expect(jsJwk['key_ops'], orderedEquals(['sign', 'verify']));
        expect(packageJwk.containsKey('ext'), isFalse);
        expect(packageJwk.containsKey('key_ops'), isFalse);

        final normalizedJsJwk = Map<String, dynamic>.from(jsJwk)
          ..remove('ext')
          ..remove('key_ops');
        expect(normalizedJsJwk, equals(packageJwk));
      },
    );
  });
}

Future<Uint8List> _wrapKey(
  JSSubtleCryptoWrap wrap,
  String format,
  subtle.JSCryptoKey key,
  subtle.JSCryptoKey wrappingKey,
  subtle.Algorithm algorithm,
) async {
  final wrapped = await wrap
      .wrapKey(format, key, wrappingKey, algorithm.toJS)
      .toDart;
  return wrapped.toDart.asUint8List();
}

Future<subtle.JSCryptoKey> _unwrapKey(
  JSSubtleCryptoWrap wrap,
  String format,
  Uint8List wrappedKey,
  subtle.JSCryptoKey unwrappingKey,
  subtle.Algorithm unwrapAlgorithm,
  subtle.Algorithm unwrappedKeyAlgorithm,
  List<String> keyUsages,
) {
  return wrap
      .unwrapKey(
        format,
        wrappedKey.toJS,
        unwrappingKey,
        unwrapAlgorithm.toJS,
        unwrappedKeyAlgorithm.toJS,
        true,
        keyUsages.toJS,
      )
      .toDart;
}
