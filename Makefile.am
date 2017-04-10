libcrypto_enginesdir = $(LIBCRYPTO_ENGINESDIR)
systemd_userunitdir = $(SYSTEMD_USERUNITDIR)

libcrypto_engines_LTLIBRARIES = \
	libp11-kit-engine.la

libp11_kit_engine_la_SOURCES = \
	engine.c \
	openssl-compat.h
libp11_kit_engine_la_CPPFLAGS = \
	-DP11KIT_P11_MODULE_PATH='"$(P11KIT_P11_MODULE_PATH)"'
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

systemd_userunit_DATA =  \
	p11-kit-remote.socket  \
	p11-kit-remote@.service

p11-kit-remote@.service: p11-kit-remote@.service.in
	$(AM_V_GEN) sed -e 's|@bindir[@]|$(bindir)|g' \
			-e 's|@p11kit_proxy_module[@]|$(P11KIT_PROXY_MODULE)|g' $< >$@

install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(systemd_userunitdir)/sockets.target.wants
	$(LN_S) -f ../p11-kit-remote.socket $(DESTDIR)$(systemd_userunitdir)/sockets.target.wants/p11-kit-remote.socket

uninstall-local:
	rm -f $(DESTDIR)$(systemd_userunitdir)/sockets.target.wants/p11-kit-remote.socket

CLEANFILES = \
	p11-kit-remote@.service

man_MANS = \
	libp11-kit-engine.so.1 \
	p11-kit-remote.socket.5 \
	p11-kit-remote@.service.5

EXTRA_DIST = \
	$(man_MANS) \
	p11-kit-remote.socket \
	p11-kit-remote@.service.in

DISTCHECK_CONFIGURE_FLAGS = \
	--with-libcrypto-enginesdir='$${prefix}/lib/openssl/engines' \
	--with-systemd-userunitdir='$${prefix}/lib/systemd/user' \
	--with-p11kit-proxy-module='$${prefix}/lib/p11-kit-proxy.so' \
	--with-p11kit-p11-module-path='$${prefix}/lib/pkcs11'

.DELETE_ON_ERROR:
