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
class TestCase {
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

  TestCase(
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

  factory TestCase.fromJson(Map json) {
    return TestCase(
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
    check(plaintext != null);
    check(
      generateKeyParams == null || signature == null,
      'Cannot verify signature for a generated key-pair',
    );
    check(importKeyParams != null);
    check(signVerifyParams != null);
  }
}

/// Function for importing pkcs8, spki, or raw key.
typedef ImportKeyFn<T> = Future<T> Function(
  List<int> keyData,
  Map<String, dynamic> keyImportParams,
);

/// Function for exporting pkcs8, spki or raw key.
typedef ExportKeyFn<T> = Future<List<int>> Function(T key);

/// Function for importing JWK key.
typedef ImportJsonWebKeyKeyFn<T> = Future<T> Function(
  Map<String, dynamic> jsonWebKeyData,
  Map<String, dynamic> keyImportParams,
);

/// Function for exporting JWK key.
typedef ExportJsonWebKeyKeyFn<T> = Future<Map<String, dynamic>> Function(T key);

/// Function for generating a [KeyPair].
typedef GenerateKeyPairFn<S, T> = Future<KeyPair<S, T>> Function(
  Map<String, dynamic> generateKeyPairParams,
);

/// Function for signing [data] using [key].
typedef SignBytesFn<T> = Future<List<int>> Function(
  T key,
  List<int> data,
  Map<String, dynamic> signParams,
);

/// Function for signing [data] using [key].
typedef SignStreamFn<T> = Future<List<int>> Function(
  T key,
  Stream<List<int>> data,
  Map<String, dynamic> signParams,
);

/// Function for verifying [data] using [key].
typedef VerifyBytesFn<T> = Future<bool> Function(
  T key,
  List<int> signature,
  List<int> data,
  Map<String, dynamic> verifyParams,
);

/// Function for verifying [data] using [key].
typedef VerifyStreamFn<T> = Future<bool> Function(
  T key,
  List<int> signature,
  Stream<List<int>> data,
  Map<String, dynamic> verifyParams,
);

@sealed
class TestRunner<PrivateKey, PublicKey> {
  final ImportKeyFn<PrivateKey> _importPrivateRawKey;
  final ExportKeyFn<PrivateKey> _exportPrivateRawKey;
  final ImportKeyFn<PrivateKey> _importPrivatePkcs8Key;
  final ExportKeyFn<PrivateKey> _exportPrivatePkcs8Key;
  final ImportJsonWebKeyKeyFn<PrivateKey> _importPrivateJsonWebKey;
  final ExportJsonWebKeyKeyFn<PrivateKey> _exportPrivateJsonWebKey;

  final ImportKeyFn<PublicKey> _importPublicRawKey;
  final ExportKeyFn<PublicKey> _exportPublicRawKey;
  final ImportKeyFn<PublicKey> _importPublicSpkiKey;
  final ExportKeyFn<PublicKey> _exportPublicSpkiKey;
  final ImportJsonWebKeyKeyFn<PublicKey> _importPublicJsonWebKey;
  final ExportJsonWebKeyKeyFn<PublicKey> _exportPublicJsonWebKey;

  final GenerateKeyPairFn<PrivateKey, PublicKey> _generateKeyPair;
  final SignBytesFn<PrivateKey> _signBytes;
  final SignStreamFn<PrivateKey> _signStream;
  final VerifyBytesFn<PublicKey> _verifyBytes;
  final VerifyStreamFn<PublicKey> _verifyStream;

  TestRunner({
    ImportKeyFn<PrivateKey> importPrivateRawKey,
    ExportKeyFn<PrivateKey> exportPrivateRawKey,
    ImportKeyFn<PrivateKey> importPrivatePkcs8Key,
    ExportKeyFn<PrivateKey> exportPrivatePkcs8Key,
    ImportJsonWebKeyKeyFn<PrivateKey> importPrivateJsonWebKey,
    ExportJsonWebKeyKeyFn<PrivateKey> exportPrivateJsonWebKey,
    ImportKeyFn<PublicKey> importPublicRawKey,
    ExportKeyFn<PublicKey> exportPublicRawKey,
    ImportKeyFn<PublicKey> importPublicSpkiKey,
    ExportKeyFn<PublicKey> exportPublicSpkiKey,
    ImportJsonWebKeyKeyFn<PublicKey> importPublicJsonWebKey,
    ExportJsonWebKeyKeyFn<PublicKey> exportPublicJsonWebKey,
    @required GenerateKeyPairFn<PrivateKey, PublicKey> generateKeyPair,
    @required SignBytesFn<PrivateKey> signBytes,
    @required SignStreamFn<PrivateKey> signStream,
    @required VerifyBytesFn<PublicKey> verifyBytes,
    @required VerifyStreamFn<PublicKey> verifyStream,
  })  : _importPrivateRawKey = importPrivateRawKey,
        _exportPrivateRawKey = exportPrivateRawKey,
        _importPrivatePkcs8Key = importPrivatePkcs8Key,
        _exportPrivatePkcs8Key = exportPrivatePkcs8Key,
        _importPrivateJsonWebKey = importPrivateJsonWebKey,
        _exportPrivateJsonWebKey = exportPrivateJsonWebKey,
        _importPublicRawKey = importPublicRawKey,
        _exportPublicRawKey = exportPublicRawKey,
        _importPublicSpkiKey = importPublicSpkiKey,
        _exportPublicSpkiKey = exportPublicSpkiKey,
        _importPublicJsonWebKey = importPublicJsonWebKey,
        _exportPublicJsonWebKey = exportPublicJsonWebKey,
        _generateKeyPair = generateKeyPair,
        _signBytes = signBytes,
        _signStream = signStream,
        _verifyBytes = verifyBytes,
        _verifyStream = verifyStream {
    _validate();
  }

  void _validate() {
    // Required operations
    check(_generateKeyPair != null);
    check(_signBytes != null);
    check(_signStream != null);
    check(_verifyBytes != null);
    check(_verifyStream != null);
    // Export-only and import-only formats do not make sense
    check((_importPrivateRawKey != null) == (_exportPrivateRawKey != null));
    check((_importPrivatePkcs8Key != null) == (_exportPrivatePkcs8Key != null));
    check((_importPrivateJsonWebKey != null) ==
        (_exportPrivateJsonWebKey != null));
    check((_importPublicRawKey != null) == (_exportPublicRawKey != null));
    check((_importPublicSpkiKey != null) == (_exportPublicSpkiKey != null));
    check(
        (_importPublicJsonWebKey != null) == (_exportPublicJsonWebKey != null));
  }

  Future<TestCase> generate({
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
    final pair = await _generateKeyPair(generateKeyParams);
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
    final signature = await _signBytes(
      pair.privateKey,
      plaintext,
      signVerifyParams,
    );

    T optionalCall<S, T>(T Function(S) fn, S v) => fn != null ? fn(v) : null;
    final c = TestCase(
      name,
      generateKeyParams: generateKeyParams,
      privateRawKeyData: await optionalCall(_exportPrivateRawKey, privateKey),
      privatePkcs8KeyData:
          await optionalCall(_exportPrivatePkcs8Key, privateKey),
      privateJsonWebKeyData:
          await optionalCall(_exportPrivateJsonWebKey, privateKey),
      publicRawKeyData: await optionalCall(_exportPublicRawKey, publicKey),
      publicSpkiKeyData: await optionalCall(_exportPublicSpkiKey, publicKey),
      publicJsonWebKeyData:
          await optionalCall(_exportPublicJsonWebKey, publicKey),
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
      run(TestCase.fromJson(c));
    }
  }

  void run(TestCase c) {
    group('${c.name}:', () {
      test('validate test case', () {
        c._validate();

        // Check that data matches the methods we have in the runner.
        check(_importPrivateRawKey != null || c.privateRawKeyData == null);
        check(_importPrivatePkcs8Key != null || c.privatePkcs8KeyData == null);
        check(
          _importPrivateJsonWebKey != null || c.privateJsonWebKeyData == null,
        );
        check(_importPublicRawKey != null || c.publicRawKeyData == null);
        check(_importPublicSpkiKey != null || c.publicSpkiKeyData == null);
        check(
            _importPublicJsonWebKey != null || c.publicJsonWebKeyData == null);
      });

      // Generate or import private/public key
      PrivateKey privateKey;
      PublicKey publicKey;
      if (c.generateKeyParams != null) {
        test('generateKeyPair()', () async {
          final pair = await _generateKeyPair(c.generateKeyParams);
          privateKey = pair.privateKey;
          publicKey = pair.publicKey;
          check(privateKey != null);
          check(publicKey != null);
        });
      } else {
        // Import private key
        if (c.privateRawKeyData != null) {
          test('importPrivateRawKey()', () async {
            privateKey = await _importPrivateRawKey(
              c.privateRawKeyData,
              c.importKeyParams,
            );
            check(privateKey != null);
          });
        }
        if (c.privatePkcs8KeyData != null) {
          test('importPrivatePkcs8Key()', () async {
            privateKey = await _importPrivatePkcs8Key(
              c.privatePkcs8KeyData,
              c.importKeyParams,
            );
            check(privateKey != null);
          });
        }
        if (c.privateJsonWebKeyData != null) {
          test('importPrivateJsonWebKey()', () async {
            privateKey = await _importPrivateJsonWebKey(
              c.privateJsonWebKeyData,
              c.importKeyParams,
            );
            check(privateKey != null);
          });
        }
        // Import public key
        if (c.publicRawKeyData != null) {
          test('importPublicRawKey()', () async {
            publicKey = await _importPublicRawKey(
              c.publicRawKeyData,
              c.importKeyParams,
            );
            check(publicKey != null);
          });
        }
        if (c.publicSpkiKeyData != null) {
          test('importPublicSpkiKey()', () async {
            publicKey = await _importPublicSpkiKey(
              c.publicSpkiKeyData,
              c.importKeyParams,
            );
            check(publicKey != null);
          });
        }
        if (c.publicJsonWebKeyData != null) {
          test('importPublicJsonWebKey()', () async {
            publicKey = await _importPublicJsonWebKey(
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
            await _verifyBytes(
              publicKey,
              c.signature,
              c.plaintext,
              c.signVerifyParams,
            ),
            'failed to verify signature from test case',
          );

          check(
            !await _verifyBytes(
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
            await _verifyStream(
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
            await _verifyStream(
              publicKey,
              c.signature,
              fibonacciChunkedStream(c.plaintext),
              c.signVerifyParams,
            ),
            'faile+d to verify signature from test case',
          );
        });
      }

      final signatures = <List<int>>[];
      test('signBytes(plaintext)', () async {
        final sig = await _signBytes(
          privateKey,
          c.plaintext,
          c.signVerifyParams,
        );
        check(sig != null && sig.isNotEmpty, 'failed to sign plaintext');
        signatures.add(sig);
        check(
          await _verifyBytes(publicKey, sig, c.plaintext, c.signVerifyParams),
          'failed to verify signature',
        );
        check(
          !await _verifyBytes(
            publicKey,
            flipFirstBits(sig),
            c.plaintext,
            c.signVerifyParams,
          ),
          'verified an invalid signature',
        );
      });

      test('signStream(plaintext)', () async {
        final sig = await _signStream(
          privateKey,
          Stream.value(c.plaintext),
          c.signVerifyParams,
        );
        check(sig != null && sig.isNotEmpty, 'failed to sign plaintext');
        signatures.add(sig);
        check(
          await _verifyBytes(publicKey, sig, c.plaintext, c.signVerifyParams),
          'failed to verify signature',
        );
        check(
          !await _verifyBytes(
            publicKey,
            flipFirstBits(sig),
            c.plaintext,
            c.signVerifyParams,
          ),
          'verified an invalid signature',
        );
      });

      test('signStream(fibonacciChunkedStream(plaintext))', () async {
        final sig = await _signStream(
          privateKey,
          fibonacciChunkedStream(c.plaintext),
          c.signVerifyParams,
        );
        check(sig != null && sig.isNotEmpty, 'failed to sign plaintext');
        signatures.add(sig);
        check(
          await _verifyBytes(publicKey, sig, c.plaintext, c.signVerifyParams),
          'failed to verify signature',
        );
        check(
          !await _verifyBytes(
            publicKey,
            flipFirstBits(sig),
            c.plaintext,
            c.signVerifyParams,
          ),
          'verified an invalid signature',
        );
      });

      if (_exportPrivateRawKey != null && _importPrivateRawKey != null) {
        test('export/import/signBytes raw private key', () async {
          final keyData = await _exportPrivateRawKey(privateKey);
          check(keyData != null && keyData.isNotEmpty, 'failed to export key');
          final key = await _importPrivateRawKey(keyData, c.importKeyParams);
          check(key != null, 'failed to import key');
          final sig = await _signBytes(key, c.plaintext, c.signVerifyParams);
          check(sig != null && sig.isNotEmpty, 'failed to sign plaintext');
          signatures.add(sig);
          check(
            await _verifyBytes(publicKey, sig, c.plaintext, c.signVerifyParams),
            'failed to verify signature',
          );
          check(
            !await _verifyBytes(
              publicKey,
              flipFirstBits(sig),
              c.plaintext,
              c.signVerifyParams,
            ),
            'verified an invalid signature',
          );
        });
      }

      if (_exportPrivatePkcs8Key != null && _importPrivatePkcs8Key != null) {
        test('export/import/signBytes pkcs8 private key', () async {
          final keyData = await _exportPrivatePkcs8Key(privateKey);
          check(keyData != null && keyData.isNotEmpty, 'failed to export key');
          final key = await _importPrivatePkcs8Key(keyData, c.importKeyParams);
          check(key != null, 'failed to import key');
          final sig = await _signBytes(key, c.plaintext, c.signVerifyParams);
          check(sig != null && sig.isNotEmpty, 'failed to sign plaintext');
          signatures.add(sig);
          check(
            await _verifyBytes(publicKey, sig, c.plaintext, c.signVerifyParams),
            'failed to verify signature',
          );
          check(
            !await _verifyBytes(
              publicKey,
              flipFirstBits(sig),
              c.plaintext,
              c.signVerifyParams,
            ),
            'verified an invalid signature',
          );
        });
      }

      if (_exportPrivateJsonWebKey != null &&
          _importPrivateJsonWebKey != null) {
        test('export/import/signBytes JWK private key', () async {
          final keyData = await _exportPrivateJsonWebKey(privateKey);
          check(keyData != null && keyData.isNotEmpty, 'failed to export key');
          final key =
              await _importPrivateJsonWebKey(keyData, c.importKeyParams);
          check(key != null, 'failed to import key');
          final sig = await _signBytes(key, c.plaintext, c.signVerifyParams);
          check(sig != null && sig.isNotEmpty, 'failed to sign plaintext');
          signatures.add(sig);
          check(
            await _verifyBytes(publicKey, sig, c.plaintext, c.signVerifyParams),
            'failed to verify signature',
          );
          check(
            !await _verifyBytes(
              publicKey,
              flipFirstBits(sig),
              c.plaintext,
              c.signVerifyParams,
            ),
            'verified an invalid signature',
          );
        });
      }

      if (_exportPublicRawKey != null && _importPublicRawKey != null) {
        test('export/import/verifyBytes raw public key', () async {
          final keyData = await _exportPublicRawKey(publicKey);
          check(keyData != null && keyData.isNotEmpty, 'failed to export key');
          final key = await _importPublicRawKey(keyData, c.importKeyParams);
          check(key != null, 'failed to import key');
          for (final sig in signatures) {
            check(
              await _verifyBytes(key, sig, c.plaintext, c.signVerifyParams),
              'failed to verify signature',
            );
            check(
              !await _verifyBytes(
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

      if (_exportPublicSpkiKey != null && _importPublicSpkiKey != null) {
        test('export/import/verifyBytes spki public key', () async {
          final keyData = await _exportPublicSpkiKey(publicKey);
          check(keyData != null && keyData.isNotEmpty, 'failed to export key');
          final key = await _importPublicSpkiKey(keyData, c.importKeyParams);
          check(key != null, 'failed to import key');
          for (final sig in signatures) {
            check(
              await _verifyBytes(key, sig, c.plaintext, c.signVerifyParams),
              'failed to verify signature',
            );
            check(
              !await _verifyBytes(
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

      if (_exportPublicJsonWebKey != null && _importPublicJsonWebKey != null) {
        test('export/import/verifyBytes JWK public key', () async {
          final keyData = await _exportPublicJsonWebKey(publicKey);
          check(keyData != null && keyData.isNotEmpty, 'failed to export key');
          final key = await _importPublicJsonWebKey(keyData, c.importKeyParams);
          check(key != null, 'failed to import key');
          for (final sig in signatures) {
            check(
              await _verifyBytes(key, sig, c.plaintext, c.signVerifyParams),
              'failed to verify signature',
            );
            check(
              !await _verifyBytes(
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
