AC_INIT([p11-kit OpenSSL Engine], 0.1)
AM_INIT_AUTOMAKE

LT_INIT([disable-static])

AC_PROG_CC

PKG_CHECK_MODULES([P11KIT], [p11-kit-1])
PKG_CHECK_MODULES([CRYPTO], [libcrypto])

P11KIT_ENGINESDIR=$($PKG_CONFIG --define-variable=prefix='${prefix}' --variable=enginesdir libcrypto)
AC_SUBST(P11KIT_ENGINESDIR)

AC_CONFIG_FILES(Makefile)
AC_OUTPUT
