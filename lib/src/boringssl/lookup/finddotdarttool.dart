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
