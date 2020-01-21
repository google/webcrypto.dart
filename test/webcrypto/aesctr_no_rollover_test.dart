// HACK: This is the same test cases as in `aesctr_test.dart` except we exclude
// the test with counter rollover as these are not supported by Firefox:
// https://hg.mozilla.org/projects/nss/file/38f1c92a5e1175bb8388768a209ac0efdabd1bd7/lib/freebl/ctr.c#l86
import 'aesctr_test.dart' show runner;

void main() {
  runner.runAll([
    {
      "name": "A128CTR/64 generated on boringssl/linux at 2020-01-19T16:40:39",
      "privateRawKeyData": "VPhdE6z4820SUnBmesDBSw==",
      "privateJsonWebKeyData": {
        "kty": "oct",
        "use": "enc",
        "alg": "A128CTR",
        "k": "VPhdE6z4820SUnBmesDBSw"
      },
      "plaintext": "dXJpcyBxdWlzIG1hdHRpcyBtYXNzYS4gUGhhc2VsbHVzIGNvbnZhbGxp",
      "ciphertext": "LnHSulNxQ6y+Z2rC2g8QQURwQWrI53qMPajfaef3cA0jaL+yAd3syGfz",
      "importKeyParams": {},
      "encryptDecryptParams": {
        "counter": "AAEECRAZJDFAUWR5kKnE4Q==",
        "length": 64
      }
    },
    {
      "name": "A128CTR/64 generated on chrome/linux at 2020-01-19T16:40:46",
      "privateRawKeyData": "sx/x9PWRAq+IjUKJOGpDVA==",
      "privateJsonWebKeyData": {
        "kty": "oct",
        "alg": "A128CTR",
        "k": "sx_x9PWRAq-IjUKJOGpDVA"
      },
      "plaintext":
          "RXRpYW0gc3VzY2lwaXQgZXN0IHZlbCBoZW5kcmVyaXQgYmxhbmRpdC4gTnVsbGFt",
      "ciphertext":
          "LiahUAh0wPHi2GfXs9RjESf7Govs9Rc4EZvJQ1SB1qM/vYdIznBSXHkBUw5SyoM3",
      "importKeyParams": {},
      "encryptDecryptParams": {
        "counter": "AAEECRAZJDFAUWR5kKnE4Q==",
        "length": 64
      }
    },
    {
      "name": "A128CTR/64 generated on firefox/linux at 2020-01-19T16:40:51",
      "privateRawKeyData": "tauul1rFz1pQSzowPHc1Bg==",
      "privateJsonWebKeyData": {
        "kty": "oct",
        "alg": "A128CTR",
        "k": "tauul1rFz1pQSzowPHc1Bg"
      },
      "plaintext":
          "bnQuIEluIGhlbmRyZXJpdCBwb3N1ZXJlIGxhY3VzIHZlbAp2YXJpdXMuIA==",
      "ciphertext":
          "Yvs4qLHAvfNP02lurZAX6khEG6YoARHFAvniYkn7olEh9/G21no8a/ksWA==",
      "importKeyParams": {},
      "encryptDecryptParams": {
        "counter": "AAEECRAZJDFAUWR5kKnE4Q==",
        "length": 64
      }
    },
  ]);
}
