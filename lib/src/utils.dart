import 'dart:typed_data';
import 'cryptokey.dart';

Future<Uint8List> asBuffer(Stream<List<int>> data) async {
  final result = <int>[];
  // TODO: Make this allocation stuff smarter
  await for (var chunk in data) {
    result.addAll(chunk);
  }
  return Uint8List.fromList(result);
}

String keyUsageToString(KeyUsage usage) {
  switch (usage) {
    case KeyUsage.encrypt:
      return 'encrypt';
    case KeyUsage.decrypt:
      return 'decrypt';
    case KeyUsage.sign:
      return 'sign';
    case KeyUsage.verify:
      return 'verify';
    // case KeyUsage.deriveKey:
    //   return 'deriveKey';
    case KeyUsage.deriveBits:
      return 'deriveBits';
    // case KeyUsage.wrapKey:
    //   return 'wrapKey';
    // case KeyUsage.unwrapKey:
    //   return 'unwrapKey';
  }
  // This is an invariant we want to check in production.
  throw AssertionError(
    'KeyUsage value with index: ${usage.index} is unknown',
  );
}

/// Check that [usages] is a subset of [allowedUsages], throws an
/// [ArgumentError] if:
///  * [usages] is `null`
///  * [usages] is not a subset of [allowedUsages].
///
/// The [algorithm] paramter is used specify a string that will be used in the
/// error message explaining why a given usage is not allowed.
void checkAllowedUsages(
  String algorithm,
  List<KeyUsage> usages,
  List<KeyUsage> allowedUsages,
) {
  ArgumentError.checkNotNull(usages, 'usages');
  assert(algorithm != null && algorithm != '', 'algorithm should be given');
  assert(allowedUsages != null, 'allowedUsages should be given');

  for (final usage in usages) {
    if (!allowedUsages.contains(usage)) {
      final allowedList = allowedUsages.map(keyUsageToString).join(', ');
      throw ArgumentError.value(
          usage, 'usages', '$algorithm only supports usages $allowedList');
    }
  }
}

/// Remove duplicate [usages] and sort according to index in enum.
List<KeyUsage> normalizeUsages(List<KeyUsage> usages) {
  assert(usages != null, 'usages should be checked for null');
  usages = usages.toSet().toList();
  usages.sort((a, b) => a.index.compareTo(b.index));
  return usages;
}
