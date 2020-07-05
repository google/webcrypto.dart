part of impl_js;

void fillRandomBytes(TypedData destination) {
  try {
    subtle.getRandomValues(destination);
  } on subtle.DomException catch (e) {
    throw _translateDomException(e);
  }
}
