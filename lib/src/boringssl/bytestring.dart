// ignore_for_file: non_constant_identifier_names

/// This library maps symbols from:
/// https://commondatastorage.googleapis.com/chromium-boringssl-docs/bytestring.h.html
library bytestring;

import 'dart:ffi';
import 'types.dart';
import 'lookup/lookup.dart';

/// A "CBS" (CRYPTO ByteString) represents a string of bytes in memory and
/// provides utility functions for safely parsing length-prefixed structures
/// like TLS and ASN.1 from it.
///
/// ```c
/// struct cbs_st {
///   const uint8_t *data;
///   size_t len;
/// };
/// ```
class CBS extends Struct {
  Pointer<Bytes> data;

  @IntPtr()
  int len;
}

/// CBS_init sets cbs to point to data. It does not take ownership of data.
///
/// ```c
/// void CBS_init(CBS *cbs, const uint8_t *data, size_t len);
/// ```
final CBS_init = resolve(Sym.CBS_init)
    .lookupFunc<Void Function(Pointer<CBS>, Pointer<Bytes>, IntPtr)>()
    .asFunction<void Function(Pointer<CBS>, Pointer<Bytes>, int)>();

/// A "CBB" (CRYPTO ByteBuilder) is a memory buffer that grows as needed and
/// provides utility functions for building length-prefixed messages.
///
/// ```c
/// struct cbb_st {
///   struct cbb_buffer_st *base;
///   // child points to a child CBB if a length-prefix is pending.
///   CBB *child;
///   // offset is the number of bytes from the start of |base->buf| to this |CBB|'s
///   // pending length prefix.
///   size_t offset;
///   // pending_len_len contains the number of bytes in this |CBB|'s pending
///   // length-prefix, or zero if no length-prefix is pending.
///   uint8_t pending_len_len;
///   char pending_is_asn1;
///   // is_top_level is true iff this is a top-level |CBB| (as opposed to a child
///   // |CBB|). Top-level objects are valid arguments for |CBB_finish|.
///   char is_top_level;
/// };
/// ```
class CBB extends Struct {
  Pointer<Void> base;

  @IntPtr()
  int offset;

  @Uint8()
  int pending_len_len;

  @Int8()
  int pending_is_asn1;

  @Int8()
  int is_top_level;
}

/// CBB_zero sets an uninitialised cbb to the zero state. It must be initialised
/// with CBB_init or CBB_init_fixed before use, but it is safe to call
/// CBB_cleanup without a successful CBB_init. This may be used for more uniform
/// cleanup of a CBB.
///
/// ```c
/// void CBB_zero(CBB *cbb);
/// ```
final CBB_zero = resolve(Sym.CBB_zero)
    .lookupFunc<Void Function(Pointer<CBB>)>()
    .asFunction<void Function(Pointer<CBB>)>();

/// CBB_init initialises cbb with initial_capacity. Since a CBB grows as needed,
/// the initial_capacity is just a hint. It returns one on success or zero on
/// allocation failure.
///
/// ```c
/// int CBB_init(CBB *cbb, size_t initial_capacity);
/// ```
final CBB_init = resolve(Sym.CBB_init)
    .lookupFunc<Int32 Function(Pointer<CBB>, IntPtr)>()
    .asFunction<int Function(Pointer<CBB>, int)>();

/// CBB_cleanup frees all resources owned by cbb and other CBB objects writing
/// to the same buffer. This should be used in an error case where a
/// serialisation is abandoned.
///
/// This function can only be called on a "top level" CBB, i.e. one initialised
/// with CBB_init or CBB_init_fixed, or a CBB set to the zero state with
/// CBB_zero.
///
/// ```c
/// void CBB_cleanup(CBB *cbb);
/// ```
final CBB_cleanup = resolve(Sym.CBB_cleanup)
    .lookupFunc<Void Function(Pointer<CBB>)>()
    .asFunction<void Function(Pointer<CBB>)>();

/// CBB_flush causes any pending length prefixes to be written out and any child
/// CBB objects of cbb to be invalidated. This allows cbb to continue to be used
/// after the children go out of scope, e.g. when local CBB objects are added as
/// children to a CBB that persists after a function returns. This function
/// returns one on success or zero on error.
///
/// ```c
/// int CBB_flush(CBB *cbb);
/// ```
final CBB_flush = resolve(Sym.CBB_flush)
    .lookupFunc<Int32 Function(Pointer<CBB>)>()
    .asFunction<int Function(Pointer<CBB>)>();

/// CBB_data returns a pointer to the bytes written to cbb. It does not flush
/// cbb. The pointer is valid until the next operation to cbb.
///
/// To avoid unfinalized length prefixes, it is a fatal error to call this on a
/// CBB with any active children.
///
/// ```c
/// const uint8_t *CBB_data(const CBB *cbb);
/// ```
final CBB_data = resolve(Sym.CBB_data)
    .lookupFunc<Pointer<Bytes> Function(Pointer<CBB>)>()
    .asFunction<Pointer<Bytes> Function(Pointer<CBB>)>();

/// CBB_len returns the number of bytes written to cbb. It does not flush cbb.
///
/// To avoid unfinalized length prefixes, it is a fatal error to call this on a
/// CBB with any active children.
///
/// ```c
/// size_t CBB_len(const CBB *cbb);
/// ```
final CBB_len = resolve(Sym.CBB_len)
    .lookupFunc<IntPtr Function(Pointer<CBB>)>()
    .asFunction<int Function(Pointer<CBB>)>();
