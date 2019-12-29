import 'dart:ffi';
import 'types.dart';
import 'helpers.dart';
import 'bytestring.dart';

// See:
// https://commondatastorage.googleapis.com/chromium-boringssl-docs/ec.h.html

/// point_conversion_form_t enumerates forms, as defined in X9.62 (ECDSA), for the encoding of a elliptic curve point (x,y)
///
/// ```c
/// typedef enum {
///   // POINT_CONVERSION_COMPRESSED indicates that the point is encoded as z||x,
///   // where the octet z specifies which solution of the quadratic equation y
///   // is.
///   POINT_CONVERSION_COMPRESSED = 2,
///
///   // POINT_CONVERSION_UNCOMPRESSED indicates that the point is encoded as
///   // z||x||y, where z is the octet 0x04.
///   POINT_CONVERSION_UNCOMPRESSED = 4,
///
///   // POINT_CONVERSION_HYBRID indicates that the point is encoded as z||x||y,
///   // where z specifies which solution of the quadratic equation y is. This is
///   // not supported by the code and has never been observed in use.
///   //
///   // TODO(agl): remove once node.js no longer references this.
///   POINT_CONVERSION_HYBRID = 6,
/// } point_conversion_form_t;
/// ```
const int POINT_CONVERSION_COMPRESSED = 2, POINT_CONVERSION_UNCOMPRESSED = 4;

//---------------------- Elliptic curve groups.

/// EC_GROUP_new_by_curve_name returns a fresh EC_GROUP object for the elliptic curve specified by nid, or NULL on unsupported NID or allocation failure.
///
/// ```c
/// OPENSSL_EXPORT EC_GROUP *EC_GROUP_new_by_curve_name(int nid);
/// ```
final EC_GROUP_new_by_curve_name = lookup('EC_GROUP_new_by_curve_name')
    .lookupFunc<Pointer<EC_GROUP> Function(Int32)>()
    .asFunction<Pointer<EC_GROUP> Function(int)>();

/// EC_GROUP_free releases a reference to group.
///
/// ```c
/// OPENSSL_EXPORT void EC_GROUP_free(EC_GROUP *group);
/// ```
final EC_GROUP_free = lookup('EC_GROUP_free')
    .lookupFunc<Void Function(Pointer<EC_GROUP>)>()
    .asFunction<void Function(Pointer<EC_GROUP>)>();

/// The supported NIDs are:
/// NID_secp224r1 (P-224),
/// NID_X9_62_prime256v1 (P-256),
/// NID_secp384r1 (P-384),
/// NID_secp521r1 (P-521)
///
/// ```c
/// #define NID_secp224r1 713
/// #define NID_X9_62_prime256v1 415
/// #define NID_secp384r1 715
/// #define NID_secp521r1 716
/// ```
const int NID_secp224r1 = 713,
    NID_X9_62_prime256v1 = 415,
    NID_secp384r1 = 715,
    NID_secp521r1 = 716;

/// EC_GROUP_get0_order returns a pointer to the internal BIGNUM object in group
/// that specifies the order of the group.
///
/// ```c
/// OPENSSL_EXPORT const BIGNUM *EC_GROUP_get0_order(const EC_GROUP *group);
/// ```
final EC_GROUP_get0_order = lookup('EC_GROUP_get0_order')
    .lookupFunc<Pointer<BIGNUM> Function(Pointer<EC_GROUP>)>()
    .asFunction<Pointer<BIGNUM> Function(Pointer<EC_GROUP>)>();

/// EC_GROUP_get_curve_name returns a NID that identifies group.
///
/// ```c
/// OPENSSL_EXPORT int EC_GROUP_get_curve_name(const EC_GROUP *group);
/// ```
final EC_GROUP_get_curve_name = lookup('EC_GROUP_get_curve_name')
    .lookupFunc<Int32 Function(Pointer<EC_GROUP>)>()
    .asFunction<int Function(Pointer<EC_GROUP>)>();

//---------------------- Points on elliptic curves.

/// EC_POINT_new returns a fresh EC_POINT object in the given group, or NULL on error.
///
/// ```c
/// OPENSSL_EXPORT EC_POINT *EC_POINT_new(const EC_GROUP *group);
/// ```
final EC_POINT_new = lookup('EC_POINT_new')
    .lookupFunc<Pointer<EC_POINT> Function(Pointer<EC_GROUP>)>()
    .asFunction<Pointer<EC_POINT> Function(Pointer<EC_GROUP>)>();

/// EC_POINT_free frees point and the data that it points to.
///
/// ```c
/// OPENSSL_EXPORT void EC_POINT_free(EC_POINT *point);
/// ```
final EC_POINT_free = lookup('EC_POINT_free')
    .lookupFunc<Void Function(Pointer<EC_POINT>)>()
    .asFunction<void Function(Pointer<EC_POINT>)>();

//---------------------- Point conversion.

/// EC_POINT_point2cbb behaves like EC_POINT_point2oct but appends the
/// serialised point to cbb. It returns one on success and zero on error.
///
/// ```c
/// OPENSSL_EXPORT int EC_POINT_point2cbb(CBB *out, const EC_GROUP *group,
///                                       const EC_POINT *point,
///                                       point_conversion_form_t form,
///                                       BN_CTX *ctx);
/// ```
final EC_POINT_point2cbb = lookup('EC_POINT_point2cbb')
    .lookupFunc<
        Int32 Function(Pointer<CBB>, Pointer<EC_GROUP>, Pointer<EC_POINT>,
            Int32, Pointer<BN_CTX>)>()
    .asFunction<
        int Function(Pointer<CBB>, Pointer<EC_GROUP>, Pointer<EC_POINT>, int,
            Pointer<BN_CTX>)>();

/// EC_POINT_oct2point sets point from len bytes of X9.62 format serialisation in buf. It returns one on success and zero otherwise. The ctx argument may be used if not NULL.
///
/// ```c
/// OPENSSL_EXPORT int EC_POINT_oct2point(const EC_GROUP *group, EC_POINT *point,
///                                       const uint8_t *buf, size_t len,
///                                       BN_CTX *ctx);
/// ```
final EC_POINT_oct2point = lookup('EC_POINT_oct2point')
    .lookupFunc<
        Int32 Function(Pointer<EC_GROUP>, Pointer<EC_POINT>, Pointer<Bytes>,
            IntPtr, Pointer<BN_CTX>)>()
    .asFunction<
        int Function(Pointer<EC_GROUP>, Pointer<EC_POINT>, Pointer<Bytes>, int,
            Pointer<BN_CTX>)>();
