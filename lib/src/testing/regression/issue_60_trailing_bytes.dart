// Copyright 2026 Google LLC
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

import 'dart:convert';
import 'dart:typed_data';
import 'package:webcrypto/webcrypto.dart';
import '../utils/utils.dart';

void main() => tests().runTests();

const _isWeb = bool.fromEnvironment('dart.library.js_util');

const _ecPkcs8 = '''
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYLo96dEstESlXmgZW
    deQoLYOSpUzxzaTFzdc/KtJzoGhRANCAATdpa7vSPqEDzyhDB3JIXi8NL5pByNzLM
    xq9CirGP9PzaxiW58t+I0KzUNUwy0McBdzuYAKBFPhGgjzvYJxIExE
  '''.replace(RegExp(r'\s+'), '');
const _ecSpki = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3aWu70j6hA88oQwdySF4vDS+aQcjcyzMavQoqxj/T82sYlufLfiNCs1DVMMtDHAXc7mACgRT4RoI872CcSBMRA==';
const _rsaPkcs8 = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC8zCW8WOYo2owIPqk4EQHZSBYAt7VVlnC2LuFINBV1UFQL4A3IslEf82y9KAU7PkJ9Pm+6GjT7Do3naqVpSa7cpkrdm0rF9h127hMw92+S98Q8yW0/iLITrsf0JDR/KsCh0g1oH5tDM0rAwxutD2ROVg1w3dubHouRV6buSP7YXx0vgpJjLZT9l3M6BTmnqxJIk/9W2wfuILLmhpUtVSuUMykYaZ/+UWz8Qzs2ZUaKrA145LqiN9g4LdWb0rf7rKRGBbp0FUDMNkq21wf21DVhHSd0CFMlDfXBbQb+Sm/mDG75uJpJpDzWTNLmseFmv+jzODn9GEwjAXSr4C71EqZXAgMBAAECggEABg2bWJGW4jQ3m5j0DRci8pfsFKyyvZCIO+1UMVGrEZHxM3UojcG+S3RJxh5bllvlqZ4avkXEKjR8CHiiF32LZ17/w0S3r8q3S8r6+BhjRxFaWlgigHPBpIwiJi1n4QmsNBlWGdDeDS2iJ5kg8M+haY9XMd6lyKIyoj/EMLfaMwCXJD+RWsOz+pI2Mrrn+AgMoksnNJM3ywskEquYy5ceRvwbQIubnligMSE69JB40Jxg7GvylVpXO0NSXoi3DviFL3sOMAGbiWhMZ62b+d81U2/L8Lpkq7SBanR2poEQtGIasfhb7JnZjd5LXtjqgliVVEzszVSosCMzRUuhAn58IQKBgQDdhLEPlPiyRAwOU162Pj+6nvFlLnnalvp3YIxa5LmUrtiabOQvvz8O97rBTu+H8a6VssGtrEWX37m1Ke+IuWqbi4jYNEQag2yLbxhyiWEPyUYa3eZJm1zDKcdRl4oQujW7ljc2lxzGlokYGxqv4ypj4XfsmYw1Ap2baMt7IA9w0QKBgQDaL47Vws0kPO0GUwr0Yu7NIumxPpi3LxL0fXnMdiFIzSgktBSIXI2HpaCTTDSA8Im6cQEZVm81cToOihFlT2LXrvcqB2taJKMUvibVmji5RZ1EfCDPmcQs6V81RtarQ0SBDHgFZyDDnu9s5itr+dG+yskrjjpIjFW74VrzK7KupwKBgDKrmpDU47prRFK2kVCglpVKrC8X3Xm51VsfM5vK/ARdpmBUjjG5zmPPGOIE+1eeWfAWLqVaZaTi4Sjmics9lnw0A75o3jcuXtLaO75fXFtvD+EvZvDpX+Ool9Y7ErLW1Vmud7y9/jAS2RMxh/45uUWVmof9a4voqEKXSwxD/iQxAoGAWK0zlFWUIsJQY12k+iarf9xMtqkGUI1lWtEUi7EHXhtj0WcPYUyciSEb3kH+pNkeYRREqhOjJ0lZm0cqQs69EYQfGInja8OwNGIETpRbsZFFlewNOdL5FHfVJkYgQYMZeImkzi1X96nFDbGOvFfQk4a/tGAd+BZxUecJnAOKn8kCgYEAr2NP39L1eCMcWqyah+dcd5AYnPOk0QZaDR+0xLZ4xK7KFIBPQnLXBlDjyh7i8V7zB5kdzRKk7YiW4mGrkSmgvEZCnkGQlTsc5mYX8dmZuwx/X85J5fpZD+yfj84M3y5ZtQ3YmhWK5gIa4VrAH57bUWyME7BX9Z+fubGnkI156u8=';
const _rsaSpki = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvMwlvFjmKNqMCD6pOBEB2UgWALe1VZZwti7hSDQVdVBUC+ANyLJRH/NsvSgFOz5CfT5vuho0+w6N52qlaUmu3KZK3ZtKxfYddu4TMPdvkvfEPMltP4iyE67H9CQ0fyrAodINaB+bQzNKwMMbrQ9kTlYNcN3bmx6LkVem7kj+2F8dL4KSYy2U/ZdzOgU5p6sSSJP/VtsH7iCy5oaVLVUrlDMpGGmf/lFs/EM7NmVGiqwNeOS6ojfYOC3Vm9K3+6ykRgW6dBVAzDZKttcH9tQ1YR0ndAhTJQ31wW0G/kpv5gxu+biaSaQ81kzS5rHhZr/o8zg5/RhMIwF0q+Au9RKmVwIDAQAB';

List<({String name, Future<void> Function() test})> tests() {
  final tests = <({String name, Future<void> Function() test})>[];
  void test(String name, Future<void> Function() fn) =>
      tests.add((name: name, test: fn));

  test('Ecdsa: importPkcs8Key rejects trailing bytes', () async {
    final key = base64Decode(_ecPkcs8);
    final badKey = Uint8List.fromList([...key, 0]);

    // Verify valid key imports normally.
    await EcdsaPrivateKey.importPkcs8Key(key, EllipticCurve.p256);

    // Verify key with trailing bytes is rejected.
    bool threw = false;
    try {
      await EcdsaPrivateKey.importPkcs8Key(badKey, EllipticCurve.p256);
    } on FormatException {
      threw = true;
    }
    if (!_isWeb) {
      check(threw, 'Should throw FormatException for trailing bytes');
    }
  });

  test('Ecdsa: importSpkiKey rejects trailing bytes', () async {
    final key = base64Decode(_ecSpki);
    final badKey = Uint8List.fromList([...key, 0]);

    await EcdsaPublicKey.importSpkiKey(key, EllipticCurve.p256);

    bool threw = false;
    try {
      await EcdsaPublicKey.importSpkiKey(badKey, EllipticCurve.p256);
    } on FormatException {
      threw = true;
    }
    check(threw, 'Should throw FormatException for trailing bytes');
  });

  test('RsaPss: importPkcs8Key rejects trailing bytes', () async {
    final key = base64Decode(_rsaPkcs8);
    final badKey = Uint8List.fromList([...key, 0]);

    await RsaPssPrivateKey.importPkcs8Key(key, Hash.sha256);

    bool threw = false;
    try {
      await RsaPssPrivateKey.importPkcs8Key(badKey, Hash.sha256);
    } on FormatException {
      threw = true;
    }
    if (!_isWeb) {
      check(threw, 'Should throw FormatException for trailing bytes');
    }
  });

  test('RsaPss: importSpkiKey rejects trailing bytes', () async {
    final key = base64Decode(_rsaSpki);
    final badKey = Uint8List.fromList([...key, 0]);

    await RsaPssPublicKey.importSpkiKey(key, Hash.sha256);

    bool threw = false;
    try {
      await RsaPssPublicKey.importSpkiKey(badKey, Hash.sha256);
    } on FormatException {
      threw = true;
    }
    check(threw, 'Should throw FormatException for trailing bytes');
  });

  return tests;
}
