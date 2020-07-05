Design Rationale
================
This section attempts to outline the thinking behind the design.

Basis in Web Cryptography
-------------------------
Today cryptography is used many places, it is often a fundamental requirement
for using any modern Web API, including cloud APIs from most cloud providers.
This means that any part of the dart eco-system which uses a cloud API will
depend on a cryptograpy package either directly or indirectly. To avoid platform
specific implementations of various client libraries and frameworks built
on top of such libraries, it is essential to have a cross platform cryptography
package.

Hence, this package aims to work whether compiled to JS for execution in a
modern web-browser, executed directly on the dart-vm or AOT compiled into a
smart-phone application. To work in the browser, this package does not provide
any logic not available in the [Web Cryptography specification][1]. In fact
this package is mostly just a wrapper around the WebCrypto APIs.

While platform independence could also be achieved by rolling a custom
cryptography implementation. This option comes with significant draw backs:

 * Custom implementations of cryptographic algorithms requires domain experts
   and extensive security reviews.
 * A Javascript implementation is unlikely to achieve performance comparable to
   the native crytography algorithms shipped with the browser.
 * A Javascript implementation would need to use WebWorker to off-load
   computation from the main-thread, while the browsers native implementation
   can do this for free.
 * Shipping custom cryptography implementations with every web application would
   increase code size and increase load time in the browser.

There are many other down sides to shipping custom implementations of
cryptography algorithms. The cost of using Web Cryptography is mostly that it
limits the flexibility of the cryptography APIs. Unlike the cryptography package
for golang, this package will not provide low-level access to underlying
primitives. However, most Dart developers are also unlikely to need such
advanced features for using a modern Web API.

Crytography is not simple, and should not be simplfied
------------------------------------------------------
This isn't entirely true of course, cryptography isn't so hard _if_ you know
what you're doing. If you don't know what you're doing, then you shouldn't be
doing cryptography! For this reason this package will not attempt to simplify
cryptography APIs.

In practice this means that this package will avoid unnecessary helper methods,
default values and utilities to make common operations easier. For example,
users will have to find PEM decoding in another package. And the RSA primitives
does not have a default exponent of `65537`, even if this is often recommended
and browsers only support `3` and `65537`. If a user wants high-level APIs, they
should find a high-level oppininated package that uses `package:webcrypto`
internally instead.

The thinking to not over simplify is in line with how the
[WebCrypto specification][1] puts the cryptography API at `crypto.subtle` in an
attempt to indicate that many of the methods have subtle usage requirements.
About the `SubleCrypto` the specification says:

> It is named `SubtleCrypto` to reflect the fact that many of these algorithms
> have subtle usage requirements in order to provide the required algorithmic
> security guarantees.

Following this line of thought, this package shall not attempt to simplify
cryptography. But instead expect that developers are reasonably competent, as
novice developers are better served using a high-level oppininated package.

[1]: https://www.w3.org/TR/WebCryptoAPI/

Divergence from `package:crypto`
--------------------------------
This does not follow `package:crypto` by implementing `Converter<S,T>`
because `convert()` cannot be asynchronous as required by WebCrypto.

Besides users (hint Flutter) would likely prefer to avoid heavy computations
like crypto on the main-thread. Even if an initial implemention doesn't move
computation off-the-mainthread, it would be preferable to keep the option open
by returning futures.

Finally, it can be argued that applying encryption using a _verb_ like
`convert` is likely to cause ambiguity, which is highly undesirable in
a cryptography library.


Avoid establishing abstractions that doesn't fit
------------------------------------------------
This packages does not aim to establish the common abstractions for easily
swappable cryptographic primitives. Mostly because such abstractions are
unlikely to fit all algorithms well, or be heavily opinionated.

Further more, the choice of cryptographic algorithm usually involves multiple
parties, client and a server or old client and new client, and all such parties
needs to agree on the cryptographic algorithms used. Thus, it's rarely possible
to just swap out the cryptographic algorithms regardless of the abstractions.

For example, while it would be easy to make an abstraction representing a
primitive that can sign/verify or encrypt/decrypt a byte-stream, the different
algorithms have different options and security guarantees. So swapping
algorithms is not easily done anyways. The only exception to this rule is
`Hash` which represents an abstract hash functions, and swapping hash primitives
is sometimes useful.


Exposed reasonably typed APIs
-----------------------------
Types are useful for documentation, auto-completion and ensuring correctness.
However, this packages does not attempt to express every conceivable state
or relationship with typing. For example, the curve of a _ECDH public-key_ is
not expressed in the `EcdhPublicKey` type, even though deriving bits from keys
with different curves will always throw.

The typed API for Web Cryptography APIs offered by this API also aims to be
flexible enough to support future options that might be added in the
Web Cryptography APIs. This means using long convoluted type names, like
`RsassaPkcs1V15PrivateKey`, even if the name is quite possibly objectively ugly.
Because elegant opinionated abstractions is not a goal for this package.
Besides it doesn't hurt to be a little verbose when doing cryptography.

In general, the API is centered around key objects with types on the form
`<Algorithm><KeyType>Key`, where `<Algorithm>` is `Hmac`, `Ecdh`, etc. and
`<KeyType>` is `Secret`, `Private` or `Public`. This allows new classes to be
introduced, if new primitives is widely adopted in the Web Cryptography
implementations shipped in various browsers.

All operations are exposed as _static methods_ or _instance methods_ on the
`<Algorithm><KeyType>Key` key classes. This allows methods to be typed with
parameters specific to the underlying primitive. This is in contrast to the
Web Cryptography specification where `window.crypto.subtle.encrypt` method takes
widely different options depending on what kind of `CryptoKey` is used.

Further more, by placing all the methods that operate on an `HmacSecretKey` as
either static functions or instance methods on the class ensures that they are
easy to discover and don't pollute the global namespace.
