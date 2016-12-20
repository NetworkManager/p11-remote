PKGCONFIG = pkg-config

libcrypto_CFLAGS = $(shell $(PKGCONFIG) --cflags libcrypto)
ENGINESDIR = $(shell $(PKGCONFIG) --variable=enginesdir libcrypto)

p11kit_CFLAGS = $(shell $(PKGCONFIG) --cflags p11-kit-1)
p11kit_LIBS = $(shell $(PKGCONFIG) --libs p11-kit-1)

LIBRARY_CFLAGS = -fPIC

CFLAGS = -g -Wall
override CFLAGS += $(LIBRARY_CFLAGS)
override CFLAGS += $(p11kit_CFLAGS)
override CFLAGS += $(libcrypto_CFLAGS)
override LDFLAGS += $(p11kit_LIBS)

all: libp11-kit.so

libp11-kit.so: engine.o
	$(CC) $(LDFLAGS) -shared -o $@ $<

install:
	mkdir -p $(DESTDIR)$(ENGINESDIR)
	install libp11-kit.so $(DESTDIR)$(ENGINESDIR)

uninstall:
	rm $(DESTDIR)$(ENGINESDIR)/libp11-kit.so

clean:
	rm -f *.so *.o
