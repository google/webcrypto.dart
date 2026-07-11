# Chromium WebCrypto test vectors

This directory contains test data from the Chromium project used to verify
that `package:webcrypto` rejects malformed keys consistently.

The vendored files are pinned to the Git revision in `REVISION` and can be
updated by running:

```console
./tool/update-chromium-test-vectors.sh [revision]
```

`bad_ec_keys.json` is retained in its upstream form, including comment-only
lines. Tests remove those lines before decoding the JSON.

Files obtained from Chromium are subject to Chromium's `LICENSE` in this
directory. The original test data is available from the
[Chromium source repository][1].

[1]: https://chromium.googlesource.com/chromium/src/+/main/components/test/data/webcrypto/bad_ec_keys.json
