all: libssl.so

libssl.so:
	make -C ../../../third_party/boringssl/ build/
	cp ../../../third_party/boringssl/build/ssl/libssl.so $@
