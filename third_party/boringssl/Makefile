
REVISION='9801a0714555f819dc6bd0f1d1a892a40465f056'

all: build/

src/:
	mkdir src/
	git clone https://boringssl.googlesource.com/boringssl src/;
	cd src/ && git reset --hard ${REVISION};

build/: src/
	mkdir build/
	# Build static library
	cd build && cmake ../src && make -j
	# Build dynamic library
	cd build && cmake -DBUILD_SHARED_LIBS=1 ../src && make -j

clean:
	rm -rf src/ build/