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
    case KeyUsage.deriveKey:
      return 'deriveKey';
    case KeyUsage.deriveBits:
      return 'deriveBits';
    case KeyUsage.wrapKey:
      return 'wrapKey';
    case KeyUsage.unwrapKey:
      return 'unwrapKey';
  }
  // This is an invariant we want to check in production.
  throw AssertionError(
    'KeyUsage value with index: ${usage.index} is unknown',
  );
}
