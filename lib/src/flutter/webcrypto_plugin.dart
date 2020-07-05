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
