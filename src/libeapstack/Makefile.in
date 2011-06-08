# First, include the real Makefile
include Makefile.real
# Then, define the other targets needed by Automake Makefiles.

EMPTY_AUTOMAKE_TARGETS = distdir install install-data install-exec uninstall install-dvi install-html install-info install-ps install-pdf installdirs check installcheck mostlyclean distclean mantainer-clean dvi pdf ps info html tags ctags

#.distdir:
#    Copy files to distribute into ‘$(distdir)’, before a tarball is constructed. Of course this target #is not required if the no-dist option (see Options) is used.

#    The variables ‘$(top_distdir)’ and ‘$(distdir)’ (see The dist Hook) will be passed from the outer #package to the subpackage when the distdir target is invoked. These two variables have been adjusted for #the directory that is being recursed into, so they are ready to use. 

.PHONY: $(EMPTY_AUTOMAKE_TARGETS)
$(EMPTY_AUTOMAKE_TARGETS):


