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
