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

import 'detected_runtime_stub.dart'
    if (dart.library.html) 'detected_runtime_html.dart';

export 'detected_runtime_stub.dart'
    if (dart.library.html) 'detected_runtime_html.dart' show detectedRuntime;

/// Return `null` instead of [value] on Firefox.
///
/// PKCS8 is not support for ECDH / ECDSA on firefox:
/// https://bugzilla.mozilla.org/show_bug.cgi?id=1133698
///
/// This utility helps filter away test cases and features known to not work on
/// Firefox and which has been documented in the API documentation.
T? nullOnFirefox<T>(T value) => detectedRuntime == 'firefox' ? null : value;

/// Return `null` instead of [value] on Safari.
///
/// This utility helps filter away test cases and features known to not work on
/// Safari and which has been documented in the API documentation.
T? nullOnSafari<T>(T value) => detectedRuntime == 'safari' ? null : value;
