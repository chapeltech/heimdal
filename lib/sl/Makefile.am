# $Id$

include $(top_srcdir)/Makefile.am.common

if do_roken_rename
ES = strtok_r.c snprintf.c strdup.c strupr.c
endif

AM_CPPFLAGS += $(ROKEN_RENAME)

AM_YFLAGS = -d -o slc-gram.c
AM_LFLAGS = @FLEXNOUNPUTARGS@

include_HEADERS = sl.h

lib_LTLIBRARIES = libsl.la
libsl_la_LDFLAGS = -version-info 2:1:2

check-abi:
	$(SHELL) $(top_srcdir)/cf/check-library-abi.sh \
	    $(top_builddir) $(top_srcdir) libsl.so $(srcdir)/abi/0

libsl_la_LIBADD = @LIB_readline@

dist_libsl_la_SOURCES = sl_locl.h sl.c roken_rename.h
nodist_libsl_la_SOURCES = $(ES)

TESTS = test_sl
check_PROGRAMS = $(TESTS)	

# install these?

libexec_heimdal_PROGRAMS = slc

slc_SOURCES = slc-gram.y slc-lex.l slc.h

CLEANFILES = snprintf.c strtok_r.c strdup.c strupr.c slc-lex.c

LDADD =	libsl.la $(LIB_roken)

slc_LDADD = $(LEXLIB) $(LDADD)

strtok_r.c:
	$(LN_S) $(srcdir)/../roken/strtok_r.c .
snprintf.c:
	$(LN_S) $(srcdir)/../roken/snprintf.c .
strdup.c:
	$(LN_S) $(srcdir)/../roken/strdup.c .
strupr.c:
	$(LN_S) $(srcdir)/../roken/strupr.c .

slc-lex.c: slc-gram.h

EXTRA_DIST = NTMakefile abi

.PHONY: check-abi
