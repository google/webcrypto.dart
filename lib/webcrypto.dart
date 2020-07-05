// Copyright 2020 Google LLC
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

/// Cryptographic primitives for use on Dart VM and Dart in the browser.
///
/// TODO: Finish documentation of a public identifiers, so far the folliwng
/// items have been documented:
///  * [fillRandomBytes]
///  * [Hash]
///  * [HmacSecretKey]
///  * [RsassaPkcs1V15PrivateKey] and [RsassaPkcs1V15PublicKey].
///
/// ## Exceptions
/// This library will throw the following exceptions:
///  * [FormatException], if input data could not be parsed.
///
/// ## Errors
/// This library will throw the following errors:
///  * [ArgumentError], when an parameter is out of range,
///  * [UnsupportedError], when an operation isn't supported,
///  * [OperationError], when an operation fails operation specific reason, this
///    typically when the underlying cryptographic library returns an error.
///
/// ## Mapping Web Crypto Error
///
///  * `SyntaxError` becomes [ArgumentError],
///  * `QuotaExceededError` becomes [ArgumentError],
///  * `NotSupportedError` becomes [UnsupportedError],
///  * `DataError` becomes [FormatException],
///  * `OperationError` becomes [OperationError],
///  * `InvalidAccessError` shouldn't occur, except for ECDH key derivation with
///     mismatching curves where it becomes an [ArgumentError].
///
library webcrypto;

export 'src/webcrypto/webcrypto.dart';
