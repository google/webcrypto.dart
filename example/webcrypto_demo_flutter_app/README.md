# webcrypto_example

This application shows how to use `package:webcrypto` for computing a SHA-1
hash of user provided string.

Additionally, this example application provides integration tests for devices.

`integration_test/rsa_key_generation_test.dart` runs RSA-OAEP key generation
with a 2048-bit modulus and exponent 65537. It is separate from the ARM32-only
`bn_word_abi_32_test.dart` so it can run on every Android ABI.
