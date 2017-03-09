ACLOCAL_AMFLAGS = -I m4
DISTCHECK_CONFIGURE_FLAGS=--with-installpath=`pwd`/apxs_modules

SUBDIRS = src/asn1c src tests

TESTSDIR=$(abs_builddir)/testsdir

distclean-local:
	rm -fr $(TESTSDIR)

check: all
	cd $(srcdir) && ./tests/magtests.py --path $(TESTSDIR) --so-dir=$(abs_builddir)/src/.libs

test: check
