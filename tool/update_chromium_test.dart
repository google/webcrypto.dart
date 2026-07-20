#!/usr/bin/env dart

// Copyright 2026 Google LLC
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

// ignore_for_file: avoid_print

import 'dart:convert';
import 'dart:io';

const repo = 'https://chromium.googlesource.com/chromium/src';

Future<void> main(List<String> args) async {
  String revision;
  if (args.singleOrNull case String rev) {
    revision = rev;
  } else {
    final result = await Process.run('git', ['ls-remote', repo, 'HEAD']);
    if (result.exitCode != 0) {
      throw ProcessException('git', ['ls-remote'], result.stderr);
    }
    revision = (result.stdout as String).split(RegExp(r'\s+')).first;
  }
  await File('third_party/chromium/REVISION').writeAsString('$revision\n');

  final url =
      '$repo/+/$revision/components/test/data/webcrypto/bad_ec_keys.json?format=TEXT';
  final request = await HttpClient().getUrl(Uri.parse(url));
  final jsonBytes = await request
      .close()
      .then((response) => response.transform(utf8.decoder).join())
      .then((base64Text) => base64Text.replaceAll(RegExp(r'\s+'), ''))
      .then((base64Text) => base64.decode(base64Text));

  await File('third_party/chromium/bad_ec_keys.json').writeAsBytes(jsonBytes);

  print(
    'Vendored Chromium WebCrypto test vectors to third_party/chromium/'
    'bad_ec_keys.json at revision $revision.',
  );
}
