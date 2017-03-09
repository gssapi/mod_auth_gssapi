AM_CPPFLAGS = -I $(srcdir)/asn1c

magdir = $(APXS_LIBEXECDIR)
mag_LTLIBRARIES = \
    mod_auth_gssapi.la

dist_noinst_HEADERS = \
    mod_auth_gssapi.h crypto.h sessions.h environ.h

mod_auth_gssapi_la_SOURCES = \
    mod_auth_gssapi.c crypto.c sessions.c environ.c
mod_auth_gssapi_la_CFLAGS = \
    $(MAG_CFLAGS)
mod_auth_gssapi_la_LIBADD = \
    asn1c/libmagasn1.la
mod_auth_gssapi_la_LDFLAGS = \
    $(MAG_LIBS) \
    -avoid-version \
    -module \
    -export-symbols-regex auth_gssapi_module

install-exec-local:
	test -d $(DESTDIR)$(APXS_LIBEXECDIR) || mkdir -p $(DESTDIR)$(APXS_LIBEXECDIR)
	@APXS@ -i -n mod_auth_gssapi -S LIBEXECDIR=$(DESTDIR)$(APXS_LIBEXECDIR) mod_auth_gssapi.la

clean-local:
	rm -f mod_auth_gssapi.slo mod_auth_gssapi.la mod_auth_gssapi.lo .libs
