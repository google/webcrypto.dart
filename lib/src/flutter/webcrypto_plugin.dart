/// Boiler-plate that allows us to add `web` in `pubspec.yaml`.
///
/// ```yaml
/// flutter:
///   plugin:
///     platforms:
///       web:
///         pluginClass: WebcryptoPlugin
///         filename: src/flutter/webcrypto_plugin.dart
/// ```
///
/// Having the `web` annotation is important for correct platform detection by
/// `pub.dev`, but since this package otherwise relies on _conditional imports_
/// this plugin does nothing.
library webcrypto_plugin;

import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_web_plugins/flutter_web_plugins.dart';

class WebcryptoPlugin {
  static void registerWith(Registrar registrar) {
    final channel = MethodChannel(
      'plugins.flutter.io/webcrypto',
      const StandardMethodCodec(),
      registrar.messenger,
    );
    final instance = WebcryptoPlugin();
    channel.setMethodCallHandler(instance.handleMethodCall);
  }

  Future<dynamic> handleMethodCall(MethodCall call) async {
    switch (call.method) {
      default:
        throw PlatformException(
            code: 'Unimplemented',
            details: "The webcrypto plugin for web doesn't implement "
                "the method '${call.method}'");
    }
  }
}
