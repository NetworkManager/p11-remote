AC_INIT([p11-kit OpenSSL Engine], 0.1)
AM_INIT_AUTOMAKE

LT_INIT([disable-static])

AC_PROG_CC

PKG_CHECK_MODULES([P11KIT], [p11-kit-1])
PKG_CHECK_MODULES([CRYPTO], [libcrypto])

save_cflags="$CFLAGS"
AC_CHECK_FUNC([p11_kit_uri_get_p11_kit_remote],
              AC_DEFINE([HAVE_P11KIT_REMOTING], [], [Define if p11-kit remoting API is available]))
CFLAGS="$save_cflags"

P11KIT_ENGINESDIR=$($PKG_CONFIG --define-variable=prefix='${prefix}' --variable=enginesdir libcrypto)
AC_SUBST(P11KIT_ENGINESDIR)

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES(Makefile)
AC_OUTPUT