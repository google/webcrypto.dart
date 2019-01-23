TARGET := libwebcrypto_extension.so
SOURCES := \
	webcrypto_extension.cc

DART_SDK ?= /usr/lib/dart
CC := g++
CFLAGS := -fPIC -I$(DART_SDK) -DDART_SHARED_LIB
LDFLAGS := -shared -Wl,-soname,$(TARGET)
OBJECTS :=$(SOURCES:.cc=.o)

all: $(TARGET)

%.o: %.cc
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(TARGET) $(OBJECTS)

.PHONY: clean all