AC_INIT([Remoting of PKCS#11 modules across sessions], 0.3, , p11-remote)
AM_INIT_AUTOMAKE

LT_INIT([disable-static])

AC_PROG_CC

PKG_CHECK_MODULES([P11KIT], [p11-kit-1])
PKG_CHECK_MODULES([CRYPTO], [libcrypto])
PKG_CHECK_MODULES([SYSTEMD], [systemd])

AC_ARG_WITH(libcrypto-enginesdir,
	AS_HELP_STRING([--with-libcrypto-enginesdir=DIR], [the OpenSSL engine directory [default=determine automatically]]),
	LIBCRYPTO_ENGINESDIR=$with_libcrypto_enginesdir,
	LIBCRYPTO_ENGINESDIR=$($PKG_CONFIG --define-variable=prefix='${prefix}' --variable=enginesdir libcrypto))
AC_SUBST(LIBCRYPTO_ENGINESDIR)

AC_ARG_WITH(systemd-userunitdir,
	AS_HELP_STRING([--with-systemd-userunitdir=DIR], [the systemd user unit directory [default=determine automatically]]),
	SYSTEMD_USERUNITDIR=$with_systemd_userunitdir,
	SYSTEMD_USERUNITDIR=$($PKG_CONFIG --define-variable=prefix='${prefix}' --variable=systemduserunitdir systemd))
AC_SUBST(SYSTEMD_USERUNITDIR)

AC_ARG_WITH(p11kit-proxy-module,
	AS_HELP_STRING([--with-p11kit-proxy-module=DIR], [the p11-kit proxy module [default=determine automatically]]),
	P11KIT_PROXY_MODULE=$with_p11kit_proxy_module,
	P11KIT_PROXY_MODULE=$($PKG_CONFIG --define-variable=prefix='${prefix}' --variable=proxy_module p11-kit-1))
AC_SUBST(P11KIT_PROXY_MODULE)

AC_ARG_WITH(p11kit-p11-module_path,
	AS_HELP_STRING([--with-p11kit-p11-module-path=DIR], [the PKCS#11 module path [default=determine automatically]]),
	P11KIT_P11_MODULE_PATH=$with_p11kit_p11_module_path,
	P11KIT_P11_MODULE_PATH=$($PKG_CONFIG --define-variable=prefix='${prefix}' --variable=p11_module_path p11-kit-1))
AC_SUBST(P11KIT_P11_MODULE_PATH)

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES(Makefile)
AC_OUTPUT
