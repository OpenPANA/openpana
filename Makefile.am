include $(top_srcdir)/aminclude.am #Enable Doxygen support

SUBDIRS = src/libeapstack src

#Adding extra configuration files to distribution
EXTRA_DIST = doxygen.cfg doxyfiles/doxygen_header.html doxyfiles/doxygen_footer.html doxyfiles/doxygen.sty doxyfiles/header.tex autogen.sh README

#deletes subversion files during distribution
dist-hook:
	find $(distdir) -path "*.svn*" -delete
