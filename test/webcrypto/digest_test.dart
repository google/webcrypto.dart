// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:convert';
import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart';
import '../utils/utils.dart';
import '../utils/lipsum.dart';
import '../utils/ffibonacci_chunked_stream.dart';

Stream<List<int>> _utf8Stream(String data) {
  return Stream.value(utf8.encode(data));
}

void main() => runTests();

/// Run all tests, exported for use in `../run_all_tests.dart`.
void runTests({TestFn test = test}) {
  // Test hash algorithms against correct value for 'hello-world', obtained with
  // echo -n 'hello-world' | sha1sum - | cut -d ' ' -f 1 | xxd -r -p | base64

  test('SHA-1: "hello-world"', () async {
    final bytes = await Hash.sha1.digestStream(_utf8Stream('hello-world'));
    final hash = base64Encode(bytes);
    check(hash == '+7lpEX7fqRa4bftn/RHezx4zbfA=');
  });

  test('SHA-256: "hello-world"', () async {
    final bytes = await Hash.sha256.digestStream(_utf8Stream('hello-world'));
    final hash = base64Encode(bytes);
    check(hash == 'r6J7RNQ7Aqn+pB0TztwuQBbPz4fF2/mQ5ZNmmqjOKG0=');
  });

  test('SHA-384: "hello-world"', () async {
    final bytes = await Hash.sha384.digestStream(_utf8Stream('hello-world'));
    final hash = base64Encode(bytes);
    check(hash ==
        'UT6f7WCFp32YJnp1is4l/ZYnOeQKpE8xjmdkLOwZ3nIP+tmT2aMRFQGJomjVf5cE');
  });

  test('SHA-512: "hello-world"', () async {
    final bytes = await Hash.sha512.digestStream(_utf8Stream('hello-world'));
    final hash = base64Encode(bytes);
    check(hash ==
        'au78KRIqOWLJDvg09sqtADO//NYpQbemIFppXMOeJ2fbd3inrXbRc6CDueFLIQ3AISkj'
            '9IGyhceEqx/jQNf/TQ==');
  });

  test(': libsumSHA-1', () async {
    final h = Hash.sha1;
    final bytes = await h.digestStream(_utf8Stream(libsum));
    final hash = base64Encode(bytes);
    check(hash == 'nBxI1wju5YS4yWgFXBL6K/AUZmk=');
    check(hash ==
        base64Encode(
          await h.digestStream(fibonacciChunkedStream(utf8.encode(libsum))),
        ));
  });

  test('SHA-256: libsum', () async {
    final h = Hash.sha256;
    final bytes = await h.digestStream(_utf8Stream(libsum));
    final hash = base64Encode(bytes);
    check(hash == 'GbcmmlUnvPkRtNYTM4dKmqsrSXQSURg5IRJcFaL2pDI=');
    check(hash ==
        base64Encode(
          await h.digestStream(fibonacciChunkedStream(utf8.encode(libsum))),
        ));
  });

  test('SHA-384: libsum', () async {
    final h = Hash.sha384;
    final bytes = await h.digestStream(_utf8Stream(libsum));
    final hash = base64Encode(bytes);
    check(hash ==
        'O9csqdeyd4eYukVJ6L8tYrqmvjeBRL8vn/I8Ggl3F2vneuF7Xr6YkWDzw1zCLTDv');
    check(hash ==
        base64Encode(
          await h.digestStream(fibonacciChunkedStream(utf8.encode(libsum))),
        ));
  });

  test('SHA-512: libsum', () async {
    final h = Hash.sha512;
    final bytes = await h.digestStream(_utf8Stream(libsum));
    final hash = base64Encode(bytes);
    check(hash ==
        'ZceIlMsV6OHRjLmIx8yWlhxPMSXHYdd5cDjsaiRNlqMIhlQbXlFjz3PGOCncVl/pK2pm'
            'G7OyjZNdO0i+0rCXZg==');
    check(hash ==
        base64Encode(
          await h.digestStream(fibonacciChunkedStream(utf8.encode(libsum))),
        ));
  });
}
