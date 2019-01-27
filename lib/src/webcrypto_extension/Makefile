TARGET := libwebcrypto_extension.so
SOURCES := \
	webcrypto_extension.cc \
	digest.cc \
	random.cc \
	hmac.cc \
	utils.cc

DART_SDK ?= /usr/lib/dart
CC := g++
CFLAGS := -fPIC -I$(DART_SDK) -I../../../third_party/boringssl/src/include -DDART_SHARED_LIB
LDFLAGS := -shared -Wl,-soname,$(TARGET)
OBJECTS := $(addprefix obj/, $(SOURCES:.cc=.o))

all: $(TARGET)

obj/%.o: %.cc
	mkdir -p obj/
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ ../../../third_party/boringssl/build/ssl/libssl.a

clean:
	rm -f $(TARGET) $(OBJECTS)

.PHONY: clean all