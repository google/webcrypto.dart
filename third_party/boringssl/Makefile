
REVISION='6c95434cc9876dfe1cdc375c5ff04e70ebfe3770'

all: lib/

src/:
	mkdir src/
	git clone https://boringssl.googlesource.com/boringssl src/;
	cd src/ && git reset --hard ${REVISION};

build/: src/
	mkdir build/
	# Build static library
	#cd build && cmake ../src && make -j2
	# Build dynamic library
	cd build && cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=1 ../src && make -j1

lib/: build/
	mkdir lib/
	cp build/ssl/libssl.so lib/libssl.so
	cp build/crypto/libcrypto.so lib/libcrypto.so

clean:
	rm -rf src/ build/ lib/
