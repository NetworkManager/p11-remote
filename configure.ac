AC_INIT([Remoting of PKCS#11 modules across sessions], 0.2, , p11-remote)
AM_INIT_AUTOMAKE

LT_INIT([disable-static])

AC_PROG_CC

PKG_CHECK_MODULES([P11KIT], [p11-kit-1])
PKG_CHECK_MODULES([CRYPTO], [libcrypto])

save_cflags="$CFLAGS"
AC_CHECK_FUNC([p11_kit_uri_get_p11_kit_remote],
              AC_DEFINE([HAVE_P11KIT_REMOTING], [], [Define if p11-kit remoting API is available]))
CFLAGS="$save_cflags"

AC_ARG_WITH(libcrypto-enginesdir,
	AS_HELP_STRING([--with-libcrypto-enginesdir=DIR], [the OpenSSL engine directory [default=determine automatically]]),
	LIBCRYPTO_ENGINESDIR=$with_libcrypto_enginesdir,
	LIBCRYPTO_ENGINESDIR=$($PKG_CONFIG --define-variable=prefix='${prefix}' --variable=enginesdir libcrypto))
AC_SUBST(LIBCRYPTO_ENGINESDIR)

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES(Makefile)
AC_OUTPUT
