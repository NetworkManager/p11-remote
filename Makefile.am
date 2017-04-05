enginesdir = $(P11KIT_ENGINESDIR)

libcrypto_engines_LTLIBRARIES = \
	libp11-kit-engine.la

libp11_kit_engine_la_SOURCES = \
	engine.c \
	openssl-compat.h
libp11_kit_engine_la_CFLAGS = \
	$(P11KIT_CFLAGS) \
	$(CRYPTO_CFLAGS)
libp11_kit_engine_la_LIBADD = \
	$(P11KIT_LIBS) \
	$(CRYPTO_LIBS)
libp11_kit_engine_la_LDFLAGS = \
	-module \
	-avoid-version \
	$(P11KIT_LDFLAGS) \
	$(CRYPTO_LDFLAGS)
