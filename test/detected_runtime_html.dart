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

/// Detected [rendering engine][1], this is one of:
///  * `'gecko'`,
///  * `'webkit'`,
///  * `'presto'`,
///  * `'trident'`,
///  * `'edgehtml'`,
///  * `'blink'`, or,
///  * `''` if nothing could be detected.
///
/// [1]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Browser_detection_using_the_user_agent
final String detectedRuntime = () {
  final userAgent = window.navigator.userAgent ?? '';
  if (userAgent.contains('Gecko/')) {
    return 'gecko';
  }
  if (userAgent.contains('AppleWebKit/')) {
    return 'webkit';
  }
  if (userAgent.contains('Opera/')) {
    return 'presto';
  }
  if (userAgent.contains('Trident/')) {
    return 'trident';
  }
  if (userAgent.contains('Edge/')) {
    return 'edgehtml';
  }
  if (userAgent.contains('Chrome/')) {
    return 'blink';
  }
  return '';
}();
