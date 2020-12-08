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

import 'dart:html' show window;

/// Detected runtime based on [rendering engine][1], this is one of:
///  * `'firefox'` (if rendering engine is `'gecko'`),
///  * `'safari'` (if rendering engine is `'webkit'`),
///  * `'presto'` (if rendering engine is `'presto'`),
///  * `'trident'` (if rendering engine is `'trident'`),
///  * `'edgehtml'` (if rendering engine is `'edgehtml'`),
///  * `'chrome'` (if rendering engine is `'blink'`),
///  * `'unknown'` if nothing could be detected.
///
/// We use product names for firefox, safari and chrome, because these link up
/// with the terminal command line arguments for `pub run test -p <platform>`.
/// Furthermore, it seems unlikely that we'll need to test on presto, trident,
/// edgehtml as these are no longer being used in latest versions of Opera or
/// Edge.
///
/// [1]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Browser_detection_using_the_user_agent
final String detectedRuntime = () {
  final ua = window.navigator.userAgent;

  if (ua.contains('Gecko/')) {
    return 'firefox';
  }
  if (ua.contains('AppleWebKit/') &&
      !ua.contains('Chrome/') &&
      !ua.contains('Chromium/')) {
    return 'safari';
  }
  if (ua.contains('Opera/')) {
    return 'presto';
  }
  if (ua.contains('Trident/')) {
    return 'trident';
  }
  if (ua.contains('Edge/')) {
    return 'edgehtml';
  }
  if (ua.contains('Chrome/')) {
    return 'chrome';
  }
  return 'unknown';
}();
