import 'dart:convert';
import 'dart:math';

import 'package:meta/meta.dart';
import 'package:webcrypto/webcrypto.dart';
import 'package:test/test.dart';
import 'ffibonacci_chunked_stream.dart';
import 'utils.dart';
import 'lipsum.dart';

List<int> _optionalBase64Decode(dynamic data) =>
    data == null ? null : base64.decode(data as String);

Map<String, dynamic> _optionalStringMapDecode(dynamic data) =>
    data == null ? null : (data as Map).cast<String, dynamic>();

String _optionalBase64Encode(List<int> data) =>
    data == null ? null : base64.encode(data);

@sealed
class AsymmetricTestCase {
  final String name;

  // Obtain a keyPair from import or key generation
  final Map<String, dynamic> generateKeyParams;
  final List<int> privateRawKeyData;
  final List<int> privatePkcs8KeyData;
  final Map<String, dynamic> privateJsonWebKeyData;
  final List<int> publicRawKeyData;
  final List<int> publicSpkiKeyData;
  final Map<String, dynamic> publicJsonWebKeyData;

  // Plaintext to be signed, (always required)
  final List<int> plaintext;
  // Signature to be verified (invalid, if generateKeyParams != null)
  final List<int> signature;

  // Parameters for key import (always required)
  final Map<String, dynamic> importKeyParams;

  // Parameters for sign/verify (always required)
  final Map<String, dynamic> signVerifyParams;

  AsymmetricTestCase(
    this.name, {
    this.generateKeyParams,
    this.privateRawKeyData,
    this.privatePkcs8KeyData,
    this.privateJsonWebKeyData,
    this.publicRawKeyData,
    this.publicSpkiKeyData,
    this.publicJsonWebKeyData,
    this.plaintext,
    this.signature,
    this.importKeyParams,
    this.signVerifyParams,
  });

  factory AsymmetricTestCase.fromJson(Map json) {
    return AsymmetricTestCase(
      json['name'] as String,
      generateKeyParams: _optionalStringMapDecode(json['generateKeyParams']),
      privateRawKeyData: _optionalBase64Decode(json['privateRawKeyData']),
      privatePkcs8KeyData: _optionalBase64Decode(json['privatePkcs8KeyData']),
      privateJsonWebKeyData:
          _optionalStringMapDecode(json['privateJsonWebKeyData']),
      publicRawKeyData: _optionalBase64Decode(json['publicRawKeyData']),
      publicSpkiKeyData: _optionalBase64Decode(json['publicSpkiKeyData']),
      publicJsonWebKeyData:
          _optionalStringMapDecode(json['publicJsonWebKeyData']),
      plaintext: _optionalBase64Decode(json['plaintext']),
      signature: _optionalBase64Decode(json['signature']),
      importKeyParams: _optionalStringMapDecode(json['importKeyParams']),
      signVerifyParams: _optionalStringMapDecode(json['signVerifyParams']),
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'name': name,
      'generateKeyParams': generateKeyParams,
      'privateRawKeyData': _optionalBase64Encode(privateRawKeyData),
      'privatePkcs8KeyData': _optionalBase64Encode(privatePkcs8KeyData),
      'privateJsonWebKeyData': privateJsonWebKeyData,
      'publicRawKeyData': _optionalBase64Encode(publicRawKeyData),
      'publicSpkiKeyData': _optionalBase64Encode(publicSpkiKeyData),
      'publicJsonWebKeyData': publicJsonWebKeyData,
      'plaintext': _optionalBase64Encode(plaintext),
      'signature': _optionalBase64Encode(signature),
      'importKeyParams': importKeyParams,
      'signVerifyParams': signVerifyParams,
    };
  }

  void _validate() {
    check(
      generateKeyParams != null ||
          ((privateRawKeyData != null ||
                  privatePkcs8KeyData != null ||
                  privateJsonWebKeyData != null) &&
              (publicRawKeyData != null ||
                  publicSpkiKeyData != null ||
                  publicJsonWebKeyData != null)),
      'A key-pair must be generated or imported',
    );
    check(
      (privateRawKeyData != null &&
              privatePkcs8KeyData == null &&
              privateJsonWebKeyData == null) ||
          (privateRawKeyData == null &&
              privatePkcs8KeyData != null &&
              privateJsonWebKeyData == null) ||
          (privateRawKeyData == null &&
              privatePkcs8KeyData == null &&
              privateJsonWebKeyData != null) ||
          (privateRawKeyData == null &&
              privatePkcs8KeyData == null &&
              privateJsonWebKeyData == null),
      'Cannot import multiple formats',
    );
    check(
      (publicRawKeyData != null &&
              publicSpkiKeyData == null &&
              publicJsonWebKeyData == null) ||
          (publicRawKeyData == null &&
              publicSpkiKeyData != null &&
              publicJsonWebKeyData == null) ||
          (publicRawKeyData == null &&
              publicSpkiKeyData == null &&
              publicJsonWebKeyData != null) ||
          (publicRawKeyData == null &&
              publicSpkiKeyData == null &&
              publicJsonWebKeyData == null),
      'Cannot import multiple formats',
    );
    check(plaintext != null);
    check(
      generateKeyParams == null || signature == null,
      'Cannot verify signature for a generated key-pair',
    );
    check(importKeyParams != null);
    check(signVerifyParams != null);
  }
}

typedef ImportKeyFn<T> = Future<T> Function(
  List<int> keyData,
  Map<String, dynamic> keyImportParams,
);
typedef ExportKeyFn<T> = Future<List<int>> Function(T key);
typedef ImportJsonWebKeyKeyFn<T> = Future<T> Function(
  Map<String, dynamic> jsonWebKeyData,
  Map<String, dynamic> keyImportParams,
);
typedef ExportJsonWebKeyKeyFn<T> = Future<Map<String, dynamic>> Function(T key);

typedef GenerateKeyPairFn<S, T> = Future<KeyPair<S, T>> Function(
  Map<String, dynamic> generateKeyPairParams,
);

typedef SignBytesFn<T> = Future<List<int>> Function(
  T key,
  List<int> data,
  Map<String, dynamic> signParams,
);

typedef SignStreamFn<T> = Future<List<int>> Function(
  T key,
  Stream<List<int>> data,
  Map<String, dynamic> signParams,
);

typedef VerifyBytesFn<T> = Future<bool> Function(
  T key,
  List<int> signature,
  List<int> data,
  Map<String, dynamic> verifyParams,
);

typedef VerifyStreamFn<T> = Future<bool> Function(
  T key,
  List<int> signature,
  Stream<List<int>> data,
  Map<String, dynamic> verifyParams,
);

@sealed
class AsymmetricTestRunner<PrivateKey, PublicKey> {
  final ImportKeyFn<PrivateKey> importPrivateRawKey;
  final ExportKeyFn<PrivateKey> exportPrivateRawKey;
  final ImportKeyFn<PrivateKey> importPrivatePkcs8Key;
  final ExportKeyFn<PrivateKey> exportPrivatePkcs8Key;
  final ImportJsonWebKeyKeyFn<PrivateKey> importPrivateJsonWebKey;
  final ExportJsonWebKeyKeyFn<PrivateKey> exportPrivateJsonWebKey;

  final ImportKeyFn<PublicKey> importPublicRawKey;
  final ExportKeyFn<PublicKey> exportPublicRawKey;
  final ImportKeyFn<PublicKey> importPublicSpkiKey;
  final ExportKeyFn<PublicKey> exportPublicSpkiKey;
  final ImportJsonWebKeyKeyFn<PublicKey> importPublicJsonWebKey;
  final ExportJsonWebKeyKeyFn<PublicKey> exportPublicJsonWebKey;

  final GenerateKeyPairFn<PrivateKey, PublicKey> generateKeyPair;
  final SignBytesFn<PrivateKey> signBytes;
  final SignStreamFn<PrivateKey> signStream;
  final VerifyBytesFn<PublicKey> verifyBytes;
  final VerifyStreamFn<PublicKey> verifyStream;

  AsymmetricTestRunner({
    this.importPrivateRawKey,
    this.exportPrivateRawKey,
    this.importPrivatePkcs8Key,
    this.exportPrivatePkcs8Key,
    this.importPrivateJsonWebKey,
    this.exportPrivateJsonWebKey,
    this.importPublicRawKey,
    this.exportPublicRawKey,
    this.importPublicSpkiKey,
    this.exportPublicSpkiKey,
    this.importPublicJsonWebKey,
    this.exportPublicJsonWebKey,
    @required this.generateKeyPair,
    @required this.signBytes,
    @required this.signStream,
    @required this.verifyBytes,
    @required this.verifyStream,
  }) {
    _validate();
  }

  void _validate() {
    // Required operations
    check(generateKeyPair != null);
    check(signBytes != null);
    check(signStream != null);
    check(verifyBytes != null);
    check(verifyStream != null);
    // Export-only and import-only formats do not make sense
    check((importPrivateRawKey != null) == (exportPrivateRawKey != null));
    check((importPrivatePkcs8Key != null) == (exportPrivatePkcs8Key != null));
    check(
        (importPrivateJsonWebKey != null) == (exportPrivateJsonWebKey != null));
    check((importPublicRawKey != null) == (exportPublicRawKey != null));
    check((importPublicSpkiKey != null) == (exportPublicSpkiKey != null));
    check((importPublicJsonWebKey != null) == (exportPublicJsonWebKey != null));
  }

  Future<AsymmetricTestCase> generate({
    @required Map<String, dynamic> generateKeyParams,
    @required Map<String, dynamic> importKeyParams,
    @required Map<String, dynamic> signVerifyParams,
    String plaintextTemplate = libsum,
    int minPlaintext = 8,
    int maxPlaintext = libsum.length,
  }) async {
    check(minPlaintext <= maxPlaintext);
    check(maxPlaintext < plaintextTemplate.length);
    final ts = DateTime.now().toIso8601String().split('.').first; // drop secs
    final name = 'generated at $ts';

    log('generating key-pair');
    final pair = await generateKeyPair(generateKeyParams);
    final privateKey = pair.privateKey;
    final publicKey = pair.publicKey;
    check(privateKey != null);
    check(publicKey != null);

    log('picking plaintext');
    final rng = Random.secure();
    final N = rng.nextInt(maxPlaintext - minPlaintext) + minPlaintext;
    final offset = rng.nextInt(plaintextTemplate.length - N);
    final plaintext = utf8.encode(plaintextTemplate.substring(
      offset,
      offset + N,
    ));

    log('creating signature');
    final signature = await signBytes(
      pair.privateKey,
      plaintext,
      signVerifyParams,
    );

    T optionalCall<S, T>(T Function(S) fn, S v) => fn != null ? fn(v) : null;
    final c = AsymmetricTestCase(
      name,
      generateKeyParams: generateKeyParams,
      privateRawKeyData: await optionalCall(exportPrivateRawKey, privateKey),
      privatePkcs8KeyData:
          await optionalCall(exportPrivatePkcs8Key, privateKey),
      privateJsonWebKeyData:
          await optionalCall(exportPrivateJsonWebKey, privateKey),
      publicRawKeyData: await optionalCall(exportPublicRawKey, publicKey),
      publicSpkiKeyData: await optionalCall(exportPublicSpkiKey, publicKey),
      publicJsonWebKeyData:
          await optionalCall(exportPublicJsonWebKey, publicKey),
      plaintext: plaintext,
      signature: signature,
      importKeyParams: importKeyParams,
      signVerifyParams: signVerifyParams,
    );

    // Log the generated test case. This makes it easy to copy/paste the test
    // case into test files.
    log(JsonEncoder.withIndent('  ').convert(c.toJson()));

    return c;
  }

  void runAll(Iterable<Map<dynamic, dynamic>> cases) {
    for (final c in cases) {
      run(AsymmetricTestCase.fromJson(c));
    }
  }

  void run(AsymmetricTestCase c) {
    group('${c.name}:', () {
      test('validate test case', () {
        c._validate();

        // Check that data matches the methods we have in the runner.
        check(importPrivateRawKey != null || c.privateRawKeyData == null);
        check(importPrivatePkcs8Key != null || c.privatePkcs8KeyData == null);
        check(
          importPrivateJsonWebKey != null || c.privateJsonWebKeyData == null,
        );
        check(importPublicRawKey != null || c.publicRawKeyData == null);
        check(importPublicSpkiKey != null || c.publicSpkiKeyData == null);
        check(importPublicJsonWebKey != null || c.publicJsonWebKeyData == null);
      });

      // Generate or import private/public key
      PrivateKey privateKey;
      PublicKey publicKey;
      if (c.generateKeyParams != null) {
        test('generateKeyPair()', () async {
          final pair = await generateKeyPair(c.generateKeyParams);
          privateKey = pair.privateKey;
          publicKey = pair.publicKey;
          check(privateKey != null);
          check(publicKey != null);
        });
      } else {
        // Import private key
        if (c.privateRawKeyData != null) {
          test('importPrivateRawKey()', () async {
            privateKey = await importPrivateRawKey(
              c.privateRawKeyData,
              c.importKeyParams,
            );
            check(privateKey != null);
          });
        }
        if (c.privatePkcs8KeyData != null) {
          test('importPrivatePkcs8Key()', () async {
            privateKey = await importPrivatePkcs8Key(
              c.privatePkcs8KeyData,
              c.importKeyParams,
            );
            check(privateKey != null);
          });
        }
        if (c.privateJsonWebKeyData != null) {
          test('importPrivateJsonWebKey()', () async {
            privateKey = await importPrivateJsonWebKey(
              c.privateJsonWebKeyData,
              c.importKeyParams,
            );
            check(privateKey != null);
          });
        }
        // Import public key
        if (c.publicRawKeyData != null) {
          test('importPublicRawKey()', () async {
            publicKey = await importPublicRawKey(
              c.publicRawKeyData,
              c.importKeyParams,
            );
            check(publicKey != null);
          });
        }
        if (c.publicSpkiKeyData != null) {
          test('importPublicSpkiKey()', () async {
            publicKey = await importPublicSpkiKey(
              c.publicSpkiKeyData,
              c.importKeyParams,
            );
            check(publicKey != null);
          });
        }
        if (c.publicJsonWebKeyData != null) {
          test('importPublicJsonWebKey()', () async {
            publicKey = await importPublicJsonWebKey(
              c.publicJsonWebKeyData,
              c.importKeyParams,
            );
            check(publicKey != null);
          });
        }
      }

      // If signature we should verify (with bytes and stream) it
      if (c.signature != null) {
        test('verifyBytes(signature, plaintext)', () async {
          check(
            await verifyBytes(
              publicKey,
              c.signature,
              c.plaintext,
              c.signVerifyParams,
            ),
            'failed to verify signature from test case',
          );

          check(
            !await verifyBytes(
              publicKey,
              flipFirstBits(c.signature),
              c.plaintext,
              c.signVerifyParams,
            ),
            'verified an invalid signature',
          );
        });

        test('verifyStream(signature, Stream.value(plaintext))', () async {
          check(
            await verifyStream(
              publicKey,
              c.signature,
              Stream.value(c.plaintext),
              c.signVerifyParams,
            ),
            'failed to verify signature from test case',
          );
        });

        test('verifyStream(signature, fibonacciChunkedStream(plaintext))',
            () async {
          check(
            await verifyStream(
              publicKey,
              c.signature,
              fibonacciChunkedStream(c.plaintext),
              c.signVerifyParams,
            ),
            'failed to verify signature from test case',
          );
        });
      }

      final signatures = <List<int>>[];
      test('signBytes(plaintext)', () async {
        final sig = await signBytes(
          privateKey,
          c.plaintext,
          c.signVerifyParams,
        );
        check(sig != null && sig.isNotEmpty, 'failed to sign plaintext');
        signatures.add(sig);
        check(
          await verifyBytes(publicKey, sig, c.plaintext, c.signVerifyParams),
          'failed to verify signature',
        );
        check(
          !await verifyBytes(
            publicKey,
            flipFirstBits(sig),
            c.plaintext,
            c.signVerifyParams,
          ),
          'verified an invalid signature',
        );
      });

      test('signStream(plaintext)', () async {
        final sig = await signStream(
          privateKey,
          Stream.value(c.plaintext),
          c.signVerifyParams,
        );
        check(sig != null && sig.isNotEmpty, 'failed to sign plaintext');
        signatures.add(sig);
        check(
          await verifyBytes(publicKey, sig, c.plaintext, c.signVerifyParams),
          'failed to verify signature',
        );
        check(
          !await verifyBytes(
            publicKey,
            flipFirstBits(sig),
            c.plaintext,
            c.signVerifyParams,
          ),
          'verified an invalid signature',
        );
      });

      test('signStream(fibonacciChunkedStream(plaintext))', () async {
        final sig = await signStream(
          privateKey,
          fibonacciChunkedStream(c.plaintext),
          c.signVerifyParams,
        );
        check(sig != null && sig.isNotEmpty, 'failed to sign plaintext');
        signatures.add(sig);
        check(
          await verifyBytes(publicKey, sig, c.plaintext, c.signVerifyParams),
          'failed to verify signature',
        );
        check(
          !await verifyBytes(
            publicKey,
            flipFirstBits(sig),
            c.plaintext,
            c.signVerifyParams,
          ),
          'verified an invalid signature',
        );
      });

      if (exportPrivateRawKey != null && importPrivateRawKey != null) {
        test('export/import/signBytes raw private key', () async {
          final keyData = await exportPrivateRawKey(privateKey);
          check(keyData != null && keyData.isNotEmpty, 'failed to export key');
          final key = await importPrivateRawKey(keyData, c.importKeyParams);
          check(key != null, 'failed to import key');
          final sig = await signBytes(key, c.plaintext, c.signVerifyParams);
          check(sig != null && sig.isNotEmpty, 'failed to sign plaintext');
          signatures.add(sig);
          check(
            await verifyBytes(publicKey, sig, c.plaintext, c.signVerifyParams),
            'failed to verify signature',
          );
          check(
            !await verifyBytes(
              publicKey,
              flipFirstBits(sig),
              c.plaintext,
              c.signVerifyParams,
            ),
            'verified an invalid signature',
          );
        });
      }

      if (exportPrivatePkcs8Key != null && importPrivatePkcs8Key != null) {
        test('export/import/signBytes pkcs8 private key', () async {
          final keyData = await exportPrivatePkcs8Key(privateKey);
          check(keyData != null && keyData.isNotEmpty, 'failed to export key');
          final key = await importPrivatePkcs8Key(keyData, c.importKeyParams);
          check(key != null, 'failed to import key');
          final sig = await signBytes(key, c.plaintext, c.signVerifyParams);
          check(sig != null && sig.isNotEmpty, 'failed to sign plaintext');
          signatures.add(sig);
          check(
            await verifyBytes(publicKey, sig, c.plaintext, c.signVerifyParams),
            'failed to verify signature',
          );
          check(
            !await verifyBytes(
              publicKey,
              flipFirstBits(sig),
              c.plaintext,
              c.signVerifyParams,
            ),
            'verified an invalid signature',
          );
        });
      }

      if (exportPrivateJsonWebKey != null && importPrivateJsonWebKey != null) {
        test('export/import/signBytes JWK private key', () async {
          final keyData = await exportPrivateJsonWebKey(privateKey);
          check(keyData != null && keyData.isNotEmpty, 'failed to export key');
          final key = await importPrivateJsonWebKey(keyData, c.importKeyParams);
          check(key != null, 'failed to import key');
          final sig = await signBytes(key, c.plaintext, c.signVerifyParams);
          check(sig != null && sig.isNotEmpty, 'failed to sign plaintext');
          signatures.add(sig);
          check(
            await verifyBytes(publicKey, sig, c.plaintext, c.signVerifyParams),
            'failed to verify signature',
          );
          check(
            !await verifyBytes(
              publicKey,
              flipFirstBits(sig),
              c.plaintext,
              c.signVerifyParams,
            ),
            'verified an invalid signature',
          );
        });
      }

      if (exportPublicRawKey != null && importPublicRawKey != null) {
        test('export/import/verifyBytes raw public key', () async {
          final keyData = await exportPublicRawKey(publicKey);
          check(keyData != null && keyData.isNotEmpty, 'failed to export key');
          final key = await importPublicRawKey(keyData, c.importKeyParams);
          check(key != null, 'failed to import key');
          for (final sig in signatures) {
            check(
              await verifyBytes(key, sig, c.plaintext, c.signVerifyParams),
              'failed to verify signature',
            );
            check(
              !await verifyBytes(
                key,
                flipFirstBits(sig),
                c.plaintext,
                c.signVerifyParams,
              ),
              'verified an invalid signature',
            );
          }
        });
      }

      if (exportPublicSpkiKey != null && importPublicSpkiKey != null) {
        test('export/import/verifyBytes spki public key', () async {
          final keyData = await exportPublicSpkiKey(publicKey);
          check(keyData != null && keyData.isNotEmpty, 'failed to export key');
          final key = await importPublicSpkiKey(keyData, c.importKeyParams);
          check(key != null, 'failed to import key');
          for (final sig in signatures) {
            check(
              await verifyBytes(key, sig, c.plaintext, c.signVerifyParams),
              'failed to verify signature',
            );
            check(
              !await verifyBytes(
                key,
                flipFirstBits(sig),
                c.plaintext,
                c.signVerifyParams,
              ),
              'verified an invalid signature',
            );
          }
        });
      }

      if (exportPublicJsonWebKey != null && importPublicJsonWebKey != null) {
        test('export/import/verifyBytes JWK public key', () async {
          final keyData = await exportPublicJsonWebKey(publicKey);
          check(keyData != null && keyData.isNotEmpty, 'failed to export key');
          final key = await importPublicJsonWebKey(keyData, c.importKeyParams);
          check(key != null, 'failed to import key');
          for (final sig in signatures) {
            check(
              await verifyBytes(key, sig, c.plaintext, c.signVerifyParams),
              'failed to verify signature',
            );
            check(
              !await verifyBytes(
                key,
                flipFirstBits(sig),
                c.plaintext,
                c.signVerifyParams,
              ),
              'verified an invalid signature',
            );
          }
        });
      }
    });
  }
}
