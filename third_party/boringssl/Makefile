

src/:
	mkdir src/
	git clone https://boringssl.googlesource.com/boringssl src/;
	cd src/ && git reset --hard 9801a0714555f819dc6bd0f1d1a892a40465f056;

build/: src/
	mkdir build/
	cd build && cmake ../src && make -j

clean:
	rm -rf src/ build/