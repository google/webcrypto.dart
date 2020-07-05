part of impl_ffi;

void fillRandomBytes(TypedData destination) {
  final dest = destination.buffer.asUint8List(
    destination.offsetInBytes,
    destination.lengthInBytes,
  );
  _withAllocation(dest.length, (ffi.Pointer<ffi.Uint8> p) {
    _checkOp(ssl.RAND_bytes(p.cast<ssl.Bytes>(), dest.length) == 1);
    dest.setAll(0, p.asTypedList(dest.length));
  });
}
