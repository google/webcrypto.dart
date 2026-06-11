TODO:
 + Split large files into multiple parts
 + Figure out how to make it work on flutter web (also annotated in pubspec.yaml)
 + Add LICENSE file and license headers to all files
 + Write a nice README.md and cleanup doc/

# TODO: test with dart2js in release mode
# flutter drive -d web-server --release --target test_driver/app.dart
# TODO: test with dart2js in profile mode
# flutter drive -d web-server --profile --target test_driver/app.dart

Future:
 - Review all TODO: items in the source code
 - Look into https://github.com/google/wycheproof
 - Run test cases from: https://source.chromium.org/chromium/chromium/src/+/main:components/test/data/webcrypto/bad_ec_keys.json
 + Refactor test/, move everything into lib/src/
 + Figure out how to do finalizers
      https://github.com/dart-lang/sdk/blob/master/runtime/include/dart_api.h#L519-L557
      Embed this C file:
      https://github.com/dart-lang/sdk/blob/master/runtime/include/dart_api_dl.c
 - Extends test cases to cover invalid input, to ensure consistency between what
   exceptions/errors various implementations may throw.
 - Re-generate all test cases, on safari too
 + Add ios support
 + Document all public methods with examples
 - Writing missing documentation:
   - AES-GCM
   - ECDH
   - ECDSA
 - Setup testing with valgrind:
    - $ valgrind --show-mismatched-frees=no dart test/webcrypto/rsassapkcs1v15_test.dart
    - TODO: test with some deallocations disabled
    - TODO: test with finalizers disabled


flutter pub run test -p vm test/webcrypto/rsapss_test.dart | grep '^|' | sed -e 's#^| ##' > vectors.txt

Note: The following bugs might cause problems when exporting from WebKit and
      importing on other browsers. At-least this has to be tested.
https://bugs.webkit.org/show_bug.cgi?id=165436
https://bugs.webkit.org/show_bug.cgi?id=165437


# ### gLinux Emulator notes
Launch an emulator using:
  /google/bin/releases/mobile-devx-platform/crow/crow.par --run_on_cloud
Open the URL in the browser.

# ### iOS notes:
# Launch simulator with:
# $ open -a Simulator
#
# Build for simulator with:
# $ cd example/webcrypto_demo_flutter_app/; flutter build ios --simulator



Parameter Set Hacks
-------------------

```
# From testrunner.dart

@sealed
class ParameterSet {
  final String name;
  final Map<String, dynamic> generateKeyParams;
  final Map<String, dynamic> importKeyParams;
  final Map<String, dynamic> signVerifyParams;
  final Map<String, dynamic> encryptDecryptParams;
  final Map<String, dynamic> deriveParams;
  final String plaintextTemplate;
  final int minPlaintext;
  final int maxPlaintext;
  final int minDeriveLength;
  final int maxDeriveLength;

  ParameterSet({
    @required this.name,
    @required this.generateKeyParams,
    @required this.importKeyParams,
    this.signVerifyParams,
    this.encryptDecryptParams,
    this.deriveParams,
    this.plaintextTemplate = libsum,
    this.minPlaintext = 8,
    this.maxPlaintext = libsum.length,
    this.minDeriveLength = 4,
    this.maxDeriveLength = 512,
  });
}


/// Validate that [p] works with [r].
void _validateParameterSet<PrivateKey, PublicKey>(
  TestRunner<PrivateKey, PublicKey> r,
  ParameterSet p,
) {
  check(p.minPlaintext <= p.maxPlaintext);
  check(p.maxPlaintext <= p.plaintextTemplate.length);
  check(p.minDeriveLength <= p.maxDeriveLength);
}

void _generateTestCase<PrivateKey, PublicKey>(
  TestRunner<PrivateKey, PublicKey> r,
  ParameterSet p,
  void Function(String name, FutureOr Function() fn) test,
) async {
  // Ensure tests are run in order given, that subsequent tests fail if a
  // previous test has failed.
  test = _withTestDependency(test);

  test('validate parameter set', () => _validateParameterSet(r, p));

  PrivateKey privateKey;
  PublicKey publicKey;
  test('Generating key-pair', () async {
    final pair = await r._generateKeyPair(p.generateKeyParams);
    privateKey = pair.privateKey;
    publicKey = pair.publicKey;
    check(privateKey != null);
    check(publicKey != null);
  });

  List<int> plaintext;
  if (r._signBytes != null || r._encryptBytes != null) {
    final rng = Random.secure();
    final N = p.minPlaintext == p.maxPlaintext
        ? p.maxPlaintext
        : rng.nextInt(p.maxPlaintext - p.minPlaintext) + p.minPlaintext;
    final offset = rng.nextInt(p.plaintextTemplate.length - N);
    plaintext = utf8.encode(p.plaintextTemplate.substring(
      offset,
      offset + N,
    ));
  }

  List<int> signature;
  if (r._signBytes != null) {
    test('Creating signature', () async {
      signature = await r._signBytes(
        privateKey,
        plaintext,
        p.signVerifyParams,
      );
    });
  }

  List<int> ciphertext;
  if (r._encryptBytes != null) {
    test('Creating ciphertext', () async {
      ciphertext = await r._encryptBytes(
        publicKey,
        plaintext,
        p.encryptDecryptParams,
      );
    });
  }

  int derivedLength;
  List<int> derivedBits;
  if (r._deriveBits != null) {
    test('Creating derivedBits', () async {
      // Picking derivedLength
      final rng = Random.secure();
      derivedLength = p.maxDeriveLength == p.minDeriveLength
          ? p.maxDeriveLength
          : rng.nextInt(p.maxDeriveLength - p.minDeriveLength) +
              p.minDeriveLength;

      // Creating derivedBits
      derivedBits = await r._deriveBits(
        _KeyPair(privateKey: privateKey, publicKey: publicKey),
        derivedLength,
        p.deriveParams,
      );
    });
  }

  final date = DateTime.now().toIso8601String().split('T').first; // drop time

  T optionalCall<S, T>(T Function(S) fn, S v) => fn != null ? fn(v) : null;
  final c = _TestCase(
    '${p.name} generated on $detectedRuntime at $date',
    generateKeyParams: null, // omit generateKeyParams
    privateRawKeyData: await optionalCall(r._exportPrivateRawKey, privateKey),
    privatePkcs8KeyData:
        await optionalCall(r._exportPrivatePkcs8Key, privateKey),
    privateJsonWebKeyData:
        await optionalCall(r._exportPrivateJsonWebKey, privateKey),
    publicRawKeyData: await optionalCall(r._exportPublicRawKey, publicKey),
    publicSpkiKeyData: await optionalCall(r._exportPublicSpkiKey, publicKey),
    publicJsonWebKeyData:
        await optionalCall(r._exportPublicJsonWebKey, publicKey),
    plaintext: plaintext,
    signature: signature,
    ciphertext: ciphertext,
    derivedBits: derivedBits,
    importKeyParams: p.importKeyParams,
    signVerifyParams: p.signVerifyParams,
    encryptDecryptParams: p.encryptDecryptParams,
    derivedLength: derivedLength,
    deriveParams: p.deriveParams,
  );

  // Log the generated test case. This makes it easy to copy/paste the test
  // case into test files.
  log('| ' +
      JsonEncoder.withIndent('  ')
          .convert(c.toJson())
          .replaceAll('\n', '\n| '));
}


```
