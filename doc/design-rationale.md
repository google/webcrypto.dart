Design Rationale
================
This section attempts to outline the thinking behind the design.

Guiding Principals
------------------

 * Cryptography is not simple, and should not be simplified.
 * The API should be platform independent.
 * Cryptographic APIs should be asynchronous.
 * Avoid establishing abstractions that don't fit.
 * Expose reasonably typed APIs.

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

 * Custom implementations of cryptographic algorithsm requires domain experts
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
primitives. However, most dart developers are also unlikely to need such
advanced features for using a modern Web API.

Crytography is not simple, and should not be simplfied
------------------------------------------------------
This isn't entirely true of course, cryptography isn't so hard _if_ you know
what you're doing. If you don't know what you're doing, then you shouldn't be
doing cryptography! For this reason this package will not attempt to simplify
cryptography APIs.

In practice this means that when input for an algorithm is accepted as chunked
byte-stream, with the type `Stream<List<int>>`, this package will not provide
additional auxiliary methods or functions for other input types. If the user
wants to process a byte-buffer, typed `List<int>`, this package will expect the
user to know (or figure out) how to transform this into a chunked byte-stream.

The thinking to not over simplify is in line with how the
[WebCrypto specification][1] puts the cryptography API at `crypto.subtle` in an
attempt to indicate that many of the methods have subtle usage requirements.
About the `SubleCrypto` the specification says:

> It is named `SubtleCrypto` to reflect the fact that many of these algorithms
> have subtle usage requirements in order to provide the required algorithmic
> security guarantees.

Following this line of thought, this package shall not attempt to simplify
cryptography. But instead expect that developers are reasonably competent, as
notice developers are better served using a high-level oppininated package.

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

For example, while it would be easy to make an abstraction for a hash function
as `List<int> Function(Stream<List<int>> data)`, there are many algorithms that
accept a hash function as an argument and would only be unable to support custom
hash algorithms. Thus, using an enum for specifying a hash algorithm is less
surprising. An package developer who needs a swappable hash algorithm
abstraction can easily define one and what implementation this package provides.

Exposed reasonably typed APIs
-----------------------------
Types are useful for documentation, auto-completion and ensuring correctness.
However, this packages does not attempt to express every conceivable state
or relationship with typing. For example key objects that can't be extracted
have the same type as keys that can be extracted.

The typed API for Web Cryptography APIs offered by this API also aims to be
flexible enough to support future options that might be added in the
Web Cryptography APIs. This means using named parameters, even for parameters
that are required. Using named parameters for most things is slightly verbose,
but elegant opinionated abstractions is not a goal for this package. Besides it
doesn't hurt to be a little verbose when doing cryptography.

For _digest_ algorithms the public API simply exposes a single static function.
While other algorithms that operates on _keys_, gives rise to classes wrapping
the key objects. These algorithm specific key-classes all subclass a common
`CryptoKey` and feature static and instance method variants of the
`crypto.subtle` methods from the Web Cryptography specification. This allows
the `crypto.subtle` methods to be typed for each algorithm. For example, the
`crypto.subtle.encrypt` functions takes wildly different parameters depending on
which algorithm is being used.

Further more, placing all the methods that operate on an `HmacSecretKey` as
either static functions or instance methods on the class ensures that they are
easy to discover and don't pollute the global namespace.

For import/export for keys the Web Cryptography API makes it seem obvious that
we should define an enum with key-formats. However, details examination of the
specification reveals that most `CryptoKey` types only support 2 of the
key-formats used in the specifications (ECDSA public keys supports 3 formats).
Further more, it turns out that export/import of JWK keys expects JSON objects
rather than a byte-buffer, thus, we provide a `export<KeyFormat>Key` method
for each supported method. Similarly, we provide a static method for importing
each supported key-format. This also makes it easy to discover supported formats.

// TODO: Discuss wrapKey/unwrapKey/deriveKey and the intermediate objects.
