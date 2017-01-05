enginesdir = $(P11KIT_ENGINESDIR)

engines_LTLIBRARIES = libp11-kit.la
libp11_kit_la_SOURCES = engine.c openssl-compat.h
libp11_kit_la_CFLAGS = $(P11KIT_CFLAGS) $(CRYPTO_CFLAGS)
libp11_kit_la_LIBADD = $(P11KIT_LIBS) $(CRYPTO_LIBS)
libp11_kit_la_LDFLAGS = -module -avoid-version \
	$(P11KIT_LDFLAGS) $(CRYPTO_LDFLAGS)
