/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#if os(iOS)
import Flutter
#elseif os(macOS)
import FlutterMacOS
#endif

import Foundation

public class SwiftWebcryptoPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    #if os(iOS)
      let messenger = registrar.messenger()
    #else
      let messenger = registrar.messenger
    #endif

    let channel = FlutterMethodChannel(name: "webcrypto", binaryMessenger: messenger)
    let instance = SwiftWebcryptoPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    #if os(iOS)
      let platform = "iOS "
    #elseif os(macOS)
      let platform = "macOS "
    #else
      let platform = "unknown "
    #endif

    result(platform + ProcessInfo.processInfo.operatingSystemVersionString)
  }
}
