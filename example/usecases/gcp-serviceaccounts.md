Service account authorization without OAuth
===========================================

Many Google APIs including GCP APIs can be called with a signed JWT. In the
`googleapis_auth` package this is already supported using a
[partial RSA implementation][googleapis_jwt_sign]. However, this code is not
easy to write and the RSA implementation is not audited or maintained.
Dart also have a few JWT packages, some of which uses `pointycastle` for
primitives (a direct Bounty Castle port to Dart).

The official documentation for [server-to-sever authentication][server-auth]
contains the following example of how to sign a JWT for authenticating with
GCP. Once the JWT is signed it can be attached as `authorization` header in
on or more HTTP or GRPC requests, so long as it has not expired.

```python
import jwt

iat = time.time()
exp = iat + 3600
payload = {'iss': '123456-compute@developer.gserviceaccount.com',
           'sub': '123456-compute@developer.gserviceaccount.com',
           'aud': 'https://firestore.googleapis.com/google.firestore.v1beta1.Firestore'
           'iat': iat,
           'exp': exp}
additional_headers = {'kid': PRIVATE_KEY_ID_FROM_JSON}
signed_jwt = jwt.encode(payload, PRIVATE_KEY_FROM_JSON, headers=additional_headers,
                       algorithm='RS256')
```

As `'dart:crypto'` aims to be a fairly low-level library, signing a JWT is not
as simple as when using a python JWT library. Yet, it is quite possible, the
following sample demonstrates how this could be achieved with `draft4.dart`.
This uses `package:pem` for decoding, what is assumed to be a PEM encoded key.

```dart
import 'dart:typed_data' show Uint8List;
import 'dart:crypto' show RsassaPkcs1V15PrivateKey;
import 'dart:convert' show base64Url, json, utf8;
import 'package:pem' show PemCodec, PemLabel;

final _jsonToBase64 = json.fuse(utf8).fuse(base64Url).encode;

Future<String> signJwt(String privateKeyId, String privateKey) async {
  // Create JWT header
  final header = _jsonToBase64({
    'alg': 'RS256',
    'typ': 'JWT',
    'kid': privateKeyId,
  });

  // Create JWT payload
  final exp = DateTime.now().millisecondsSinceEpoch / 1000;
  final iat = exp + 3600;
  final payload = _jsonToBase64({
    'iss': '123456-compute@developer.gserviceaccount.com',
    'sub': '123456-compute@developer.gserviceaccount.com',
    'aud': 'https://firestore.googleapis.com/google.firestore.v1beta1.Firestore'
    'iat': iat,
    'exp': exp,
  });

  // Load key
  final keyData = PemCodec(PemLabel.privateKey).decode(privateKey);
  final rsaKey = await RsassaPkcs1V15PrivateKey.importPkcs8Key(
    keyData,
    Hash.sha256,
  );

  // Sign the header and payload
  final bytesToSign = Uint8List.fromList(utf8.encode('$header.$payload'));
  final signatureBytes = await rsaKey.sign(bytesToSign);
  final signature = base64Url.encode(signatureBytes);

  // Construct signed JWT
  return '$header.$payload.$signature';
}

final signedJwt = await signJwt(
  PRIVATE_KEY_ID_FROM_JSON,
  PRIVATE_KEY_FROM_JSON,
);
```


[server-auth]: https://developers.google.com/identity/protocols/OAuth2ServiceAccount#jwt-auth
[googleapis_jwt_sign]: https://github.com/dart-lang/googleapis_auth/blob/365652a5dc9d60c8d37fdbb6c8937ce616cfc842/lib/src/oauth2_flows/jwt.dart