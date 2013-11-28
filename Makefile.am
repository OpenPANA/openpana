include $(top_srcdir)/aminclude.am #Enable Doxygen support

SUBDIRS = src/libeapstack src

#Adding extra configuration files to distribution
EXTRA_DIST = doxygen.cfg doxyfiles README

#deletes subversion files during distribution
dist-hook:
	find $(distdir) -path "*.svn*" -delete && make -f Makefile.real -C $(distdir)/src/libeapstack clean
