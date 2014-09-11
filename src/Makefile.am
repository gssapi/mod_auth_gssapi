magdir = $(MAG_LIBDIR)
mag_LTLIBRARIES = \
    mod_auth_gssapi.la

dist_noinst_HEADERS = \
    mod_auth_gssapi.h crypto.h sessions.h

mod_auth_gssapi_la_SOURCES = \
    mod_auth_gssapi.c crypto.c sessions.c
mod_auth_gssapi_la_CFLAGS = \
    $(MAG_CFLAGS)
mod_auth_gssapi_la_LDFLAGS = \
    $(MAG_LIBS) \
    -avoid-version \
    -module

install-exec-local:
	if test ! -d ${APXS_LIBEXECDIR}; then mkdir -p ${APXS_LIBEXECDIR}; fi
	@APXS@ -i -S LIBEXECDIR=${APXS_LIBEXECDIR} mod_auth_gssapi.la

clean-local:
	rm -f mod_auth_gssapi.slo mod_auth_gssapi.la mod_auth_gssapi.lo .libs
