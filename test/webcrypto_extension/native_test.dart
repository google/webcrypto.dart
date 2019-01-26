import 'package:test/test.dart';
import 'package:webcrypto/src/webcrypto_extension/webcrypto_extension.dart'
    as ext;

void main() async {
  test('loading', () {
    print(ext.systemRand());
  });
}
