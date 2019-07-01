AWS Signature Version 4
=======================

A common use-case for cryptography is to sign requests for talking to cloud
services like AWS. Version 4 of the [AWS signature][sig4] uses SHA-256 and
HMAC-SHA256 for signing requests.

The popular [`aws4sign`][aws4sign] package from npm contains the following two
functions for hashing and HMAC signing strings.

```js
function hash(string, encoding) {
  return crypto.createHash('sha256').update(string, 'utf8').digest(encoding)
}

function hmac(key, string, encoding) {
  return crypto.createHmac('sha256', key).update(string, 'utf8').digest(encoding)
}
```

These functions could easily be implemented using `dart:crypto` from
`lib/draft4.dart`.

```dart
import 'dart:typed_data' show Uint8List;
import 'dart:convert' show utf8, Encoding;
import 'dart:crypto' show HmacSecretKey, Hash;

Future<String> hash(String stringToHash, Encoding encoding) async {
  final bytesToHash = Uint8List.fromList(utf8.encode(stringToHash));
  final hashBytes = await Hash.sha256.digest(bytesToHash);
  return encoding.encode(hashBytes);
}

String hmac(String key, String stringToSign, Encoding encoding) {
  final keyBytes = Uint8List.fromList(utf8.encode(key))
  final bytesToSign = Uint8List.fromList(utf8.encode(stringToSign));
  final hmac = await HmacSecretKey.importRawKey(
    keyBytes,
    Hash.sha256,
  );
  final signature = await hmac.sign(bytesToSign);
  return encoding.encode(signature);
}
```

Notice that we might approach a future where `Uint8List.fromList()` is not
necessary as once `Utf8Codec.encode` returns `Uint8List`, see
[dart-lang/sdk#36900][breaking-change] for progress.

[sig4]: https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
[aws4sign]: https://github.com/mhart/aws4/blob/master/aws4.js
[breaking-change]: https://github.com/dart-lang/sdk/issues/36900

