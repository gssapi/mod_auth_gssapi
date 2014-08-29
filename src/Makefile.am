EXTRA_DIST = mod_auth_gssapi.c sessions.c crypto.c mod_auth_gssapi.h sessions.h crypto.h

all-local:
	@APXS@ -c ${LIBS} mod_auth_gssapi.c sessions.c crypto.c

install-exec-local:
	if test ! -d ${APXS_LIBEXECDIR}; then mkdir -p ${APXS_LIBEXECDIR}; fi
	@APXS@ -i -S LIBEXECDIR=${APXS_LIBEXECDIR} mod_auth_gssapi.la

clean-local:
	rm -f mod_auth_gssapi.slo mod_auth_gssapi.la mod_auth_gssapi.lo .libs
