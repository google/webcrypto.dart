BoringSSL FFI Bindings
======================
_Brief introduction to how this package is structured._

The `boringssl.dart` library exports all symbols from BoringSSL used in
the `webcrypto_impl_ffi.dart` implementation. We seek to avoid defining symbols
that are not used.

The code doing this is structured as follows:
 * `boringssl.dart` exports everything that should be used outside.
 * `lookup/lookup.dart` provides helpers for defining symboles without having
    two type parameters on the same line (multiple lines is more readable).
 * `types.dart` defines all types, as it's not obvious from documentation
   what headers these are defined in.
 * `<name>.dart` defines symbols from `<name>.h` in the
   [BoringSSL documentation][1].

Generally, we aim to copy the documentation comments and signature from
the [BoringSSL documentation][1]. As far as possible avoid making up additional
documentation.

[1]: https://commondatastorage.googleapis.com/chromium-boringssl-docs/headers.html
