# Calls the real Makefile
all-local:
	$(MAKE) -f Makefile.real $(AM_MAKEFLAGS) all
check-local:
	$(MAKE) -f Makefile.real $(AM_MAKEFLAGS) test
clean-local:
	$(MAKE) -f Makefile.real $(AM_MAKEFLAGS) clean

EXTRA_DIST = *.c *.h Makefile.real ../wpa_supplicant

# Then, define the other targets needed by Automake Makefiles.
EMPTY_AUTOMAKE_TARGETS = distdir install install-data install-exec uninstall install-dvi install-html install-info install-ps install-pdf installdirs check installcheck mostlyclean distclean mantainer-clean dvi pdf ps info html tags ctags Makefile.real

.PHONY: $(EMPTY_AUTOMAKE_TARGETS)
$(EMPTY_AUTOMAKE_TARGETS):

