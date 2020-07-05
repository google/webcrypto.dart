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

/// This library supplies as [findDotDartTool] function that attempts to find
/// the `.dart_tool/` folder for the current _root package_. The function
/// returns `null` if unable to find it.
///
/// This split into a library using `dart:cli` and `dart:isolate` when these
/// are available, otherwise the fallback strategy is to walk up from the
/// current script path.
library finddotdarttool;

export 'finddotdarttool_fallback.dart'
    if (dart.library.cli) 'finddotdarttool_cli.dart';
