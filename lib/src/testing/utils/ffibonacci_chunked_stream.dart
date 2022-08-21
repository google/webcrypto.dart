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

/// Return the N'th fibonacci number.
int _fibonacci(int n) {
  ArgumentError.checkNotNull(n, 'n');
  if (n < 0) {
    throw ArgumentError.value(n, 'n', 'must be a non-negative integer');
  }
  if (n < 2) {
    return n;
  }
  return _fibonacci(n - 1) + _fibonacci(n - 2);
}

/// Return a stream that return fibonacci sized chunks of [data], until it hits
/// `4181` then it returns `4181` sized chunks until end of [data].
///
/// This ensures that various chunks sizes are exercised in tests.
Stream<List<T>> fibonacciChunkedStream<T>(Iterable<T> data) async* {
  var i = 0;
  while (data.isNotEmpty) {
    final n = _fibonacci(i++);
    yield data.take(n).toList();
    data = data.skip(n);
    if (n == 4181) {
      break;
    }
  }
  while (data.isNotEmpty) {
    const n = 4181;
    yield data.take(n).toList();
    data = data.skip(n);
  }
}
