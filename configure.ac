AC_PREREQ([2.69])
AC_INIT([mod_auth_gssapi], [1.0.3], [simo@redhat.com])
AC_CONFIG_SRCDIR([src/mod_auth_gssapi.c])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects tar-pax])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([src/config.h])

# Checks for programs.
AC_PROG_CC

AC_PROG_LIBTOOL
AC_SUBST(INCLTDL)
AC_SUBST(LIBLTDL)

AM_CONDITIONAL([HAVE_GCC], [test "$ac_cv_prog_gcc" = yes])

AC_CHECK_HEADERS([stdint.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_CHECK_FUNCS([strcasecmp])

AC_ARG_WITH([apxs],
            [AC_HELP_STRING([--with-apxs=PATH/NAME], [path to the apxs binary [[apxs]]])],
            [AC_SUBST(APXS, $with_apxs)],
            [AC_PATH_PROGS(APXS, [apxs2 apxs])])
AS_IF([test "x${APXS}" != "x" -a -x "${APXS}"],
      [AC_MSG_NOTICE([apxs found at $APXS])
       APXS_LIBEXECDIR=`${APXS} -q LIBEXECDIR`
       AC_SUBST(APXS_LIBEXECDIR)],
      [AC_MSG_FAILURE(["apxs not found. Use --with-apxs"])])

AC_ARG_WITH([apr],
            [AC_HELP_STRING([--with-apr=PATH/NAME], [path to the apr binary [[apr]]])],
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

PKG_CHECK_MODULES([OPENSSL], [openssl])
AC_SUBST([OPENSSL_CFLAGS])
AC_SUBST([OPENSSL_LIBS])

AC_CHECK_HEADERS([gssapi/gssapi.h],,[AC_MSG_ERROR([Could not find GSSAPI headers])])
AC_PATH_PROG(KRB5_CONFIG, krb5-config, failed)
if test x$KRB5_CONFIG = xfailed; then
    AC_MSG_ERROR([Could not find GSSAPI development libraries])
else
    GSSAPI_CFLAGS="`$KRB5_CONFIG --cflags gssapi`"
    GSSAPI_LIBS="`$KRB5_CONFIG --libs gssapi`"
fi
AC_CHECK_LIB([gssapi_krb5], [gss_accept_sec_context], [],
             [AC_MSG_ERROR([GSSAPI library check failed])])
AC_CHECK_FUNCS(gss_acquire_cred_from)
AC_CHECK_FUNCS(gss_store_cred_into)

AC_SUBST([GSSAPI_CFLAGS])
AC_SUBST([GSSAPI_LIBS])

MAG_CFLAGS="`${APXS} -q CFLAGS` `${APR} --cflags` ${GSSAPI_CFLAGS} ${OPENSSL_CFLAGS} -I`${APXS} -q INCLUDEDIR` `${APR} --includes`"
MAG_LIBS="`${APR} --libs` ${GSSAPI_LIBS} ${OPENSSL_LIBS}"
LIBTOOL="`${APXS} -q LIBTOOL`"
MAG_LIBDIR="`${APXS} -q libexecdir`"

AC_SUBST([MAG_CFLAGS])
AC_SUBST([MAG_LIBS])
AC_SUBST([LIBTOOL])
AC_SUBST([MAG_LIBDIR])

AC_CONFIG_FILES([Makefile src/Makefile])

AC_OUTPUT
