MAG_CFLAGS = @APR_CPPFLAGS@ @APXS_CPPFLAGS@ @APXS_CPPFLAGS_SHLIB@
MAG_INCLUDES = @INCLTDL@ @APR_INCLUDES@ @APXS_INCLUDES@
MAG_LIBS = @LIBLTDL@ @APR_LDFLAGS@ @APXS_LDFLAGS@ @APXS_LIBS@ @APXS_LD_SHLIB@
MAG_LIBEXECDIR = @APXS_LIBEXECDIR@

if HAVE_GCC
    MAG_CFLAGS += -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith \
                  -Wcast-qual -Wcast-align -Wwrite-strings \
                  -Werror-implicit-function-declaration \
                  -fno-strict-aliasing
endif

lib_LTLIBRARIES = mod_auth_gssapi.la

mod_auth_gssapi_la_LDFLAGS = -module

mod_auth_gssapi.la: mod_auth_gssapi.c
	@APXS@ -c ${LIBS} -Wc,"${MAG_CFLAGS} ${MAG_INCLUDES}" -Wl,"${MAG_LIBS}" mod_auth_gssapi.c

install: mod_auth_gssapi.la
	if test ! -d ${MAG_LIBEXECDIR}; then mkdir -p ${MAG_LIBEXECDIR}; fi
	@APXS@ -i -S LIBEXECDIR=${MAG_LIBEXECDIR} mod_auth_gssapi.la

clean-local:
	rm -f mod_auth_gssapi.slo mod_auth_gssapi.la mod_auth_gssapi.lo .libs
