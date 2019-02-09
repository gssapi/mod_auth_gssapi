AC_PREREQ([2.69])
m4_include([version.m4])
AC_INIT([mod_auth_gssapi],[VERSION_NUMBER],[simo@redhat.com])
AC_CONFIG_SRCDIR([src/mod_auth_gssapi.c])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects tar-pax])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([src/config.h])

# Checks for programs.
AC_PROG_CC_STDC

AC_CHECK_PROG(PKG_CONFIG_CHECK,pkg-config,yes)
if test x$PKG_CONFIG_CHECK != xyes; then
	AC_MSG_ERROR([Cannot find pkg-config. Please install pkg-config.])
fi

AC_PROG_YACC
AC_CHECK_PROG(YACC_CHECK,$YACC,yes)
if test x"$YACC_CHECK" != x"yes"; then
	AC_MSG_ERROR([Cannot find a yacc-compatible parser generator. Please install bison, byacc, or yacc.])
fi
AC_PROG_LEX
AC_CHECK_PROG(LEX_CHECK,$LEX,yes)
if test x"$LEX_CHECK" != x"yes"; then
	AC_MSG_ERROR([Cannot find a lex-compatible lexer. Please install lex, or flex.])
fi
AC_DECL_YYTEXT

LT_INIT
AC_SUBST(INCLTDL)
AC_SUBST(LIBLTDL)

AM_CONDITIONAL([HAVE_GCC], [test "$ac_cv_c_compiler_gnu" = yes])

AC_CHECK_HEADERS([stdint.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_CHECK_FUNCS([strcasecmp])

AC_PATH_PROGS(APACHE, [apache2 httpd apache])
if test x"$APACHE" == x; then
	AC_MSG_ERROR([Can't find the apache2/httpd executable!])
fi
chk="$(objdump -d "$APACHE" | grep ap_log_rdata)"
if test x"$chk" != x; then
	AC_DEFINE([HAVE_AP_LOG_RDATA], [1], [ap_log_rdata() is present])
else
	AC_MSG_WARN([Apache/httpd is missing ap_log_rdata; some logging will be disabled])
fi

AC_ARG_WITH([installpath],
            [AS_HELP_STRING([--with-installpath=PATH],
                            [alternative install path])],
            [AC_SUBST(INSTALLPATH, $with_installpath)])

AC_ARG_WITH([apxs],
            [AS_HELP_STRING([--with-apxs=PATH/NAME],[path to the apxs binary [[apxs]]])],
            [AC_SUBST(APXS, $with_apxs)],
            [AC_PATH_PROGS(APXS, [apxs2 apxs])])

AS_IF([test "x${APXS}" != "x" -a -x "${APXS}"],
      [AC_MSG_NOTICE([apxs found at $APXS])
       AS_IF([test "x${INSTALLPATH}" != "x"],
       [AC_MSG_NOTICE([installpath set at $INSTALLPATH])
        APXS_LIBEXECDIR=`echo ${INSTALLPATH}`],
        [APXS_LIBEXECDIR=`${APXS} -q LIBEXECDIR`])
       AC_SUBST(APXS_LIBEXECDIR)],
      [AC_MSG_FAILURE(["apxs not found. Use --with-apxs"])])

AC_ARG_WITH([apr],
            [AS_HELP_STRING([--with-apr=PATH/NAME],[path to the apr binary [[apr]]])],
            [AC_SUBST(APR, $with_apr)],
            [AC_PATH_PROGS(APR, [apr-1-config])])
AS_IF([test "x${APR}" != "x" -a -x "${APR}"],
      [AC_MSG_NOTICE([apr found at $APR])
       APR_CPPFLAGS=`${APR} --cppflags`
       AC_SUBST(APR_CPPFLAGS)
       APR_INCLUDES=`${APR} --includes`
       AC_SUBST(APR_INCLUDES)
       APR_LDFLAGS=`${APR} --link-libtool --libs`
       AC_SUBST(APR_LDFLAGS)],
      [AC_MSG_FAILURE(["apr-1-config not found. Use --with-apr"])])

# OpenSSL availability and presence of specific functions
PKG_CHECK_MODULES([OPENSSL], [openssl])
AC_SUBST([OPENSSL_CFLAGS])
AC_SUBST([OPENSSL_LIBS])
save_LIBS=$LIBS
LIBS="$LIBS $OPENSSL_LIBS"
AC_CHECK_FUNCS(EVP_CIPHER_CTX_new HMAC_CTX_new)
LIBS=$save_LIBS

# GSSAPI availability and presence of specific functions
AC_CHECK_HEADERS([gssapi/gssapi.h gssapi/gssapi_ext.h gssapi/gssapi_krb5.h],
                 ,[AC_MSG_ERROR([Could not find GSSAPI headers])])
AC_CHECK_HEADERS([gssapi/gssapi_ntlmssp.h])
AC_PATH_PROG(KRB5_CONFIG, krb5-config, failed)
if test x$KRB5_CONFIG = xfailed; then
    AC_MSG_ERROR([Could not find GSSAPI development libraries])
else
    GSSAPI_CFLAGS="`$KRB5_CONFIG --cflags gssapi`"
    GSSAPI_LIBS="`$KRB5_CONFIG --libs gssapi`"
fi
AC_CHECK_LIB([gssapi_krb5], [gss_accept_sec_context], [],
             [AC_MSG_ERROR([GSSAPI library check failed])])
AC_CHECK_FUNCS(gss_krb5_ccache_name, [],
               [AC_MSG_ERROR([gss_krb5_ccache_name() not found])])
AC_CHECK_FUNCS(gss_acquire_cred_with_password, [],
               [AC_MSG_ERROR([gss_acquire_with_password() not found])])
AC_CHECK_FUNCS(gss_acquire_cred_from)
AC_CHECK_FUNCS(gss_store_cred_into)

AC_SUBST([GSSAPI_CFLAGS])
AC_SUBST([GSSAPI_LIBS])

MAG_CFLAGS="`${APXS} -q CFLAGS` `${APXS} -q EXTRA_CPPFLAGS` `${APR} --cflags` ${GSSAPI_CFLAGS} ${OPENSSL_CFLAGS} -I`${APXS} -q INCLUDEDIR` `${APR} --includes` -fPIC"
MAG_LIBS="`${APR} --libs` ${GSSAPI_LIBS} ${OPENSSL_LIBS}"
LIBTOOL="`${APXS} -q LIBTOOL`"

AC_SUBST([MAG_CFLAGS])
AC_SUBST([MAG_LIBS])
AC_SUBST([LIBTOOL])

AC_CONFIG_FILES([Makefile src/Makefile src/asn1c/Makefile tests/Makefile
                 contrib/mod_auth_gssapi.spec])

AC_OUTPUT
