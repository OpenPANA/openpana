
AC_PREREQ([2.65])
AC_INIT([OpenPANA], [0.2.4], [openpana-users@lists.sourceforge.net],[openpana],[http://openpana.sf.net])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE()
AC_CONFIG_HEADERS([config.h])

# store current user given compiler flags to avoid default setup via AC_PROG_CC_C99
OLD_CFLAGS=$CFLAGS

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC_C99
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

# reset compiler flags to initial flags
CFLAGS=$OLD_CFLAGS

# Checks for libraries.
AC_CHECK_LIB([pthread], [pthread_mutex_lock])
AC_CHECK_LIB([ssl], [HMAC],[],[
		AC_CHECK_LIB([crypto], [HMAC],[],[
			echo "Error! You need to have ssl or crypto to continue. Check which of these libraries contain the HMAC function in your system and install it to continue"
			exit -1
			])
        ])
AC_CHECK_LIB([xml2], [xmlCleanupParser],[],[
        echo "Error! You need to have libxml2-dev to continue."
        exit -1
        ])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h inttypes.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h time.h unistd.h stdio.h signal.h semaphore.h pthread.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([gettimeofday inet_ntoa memset pow select socket bzero])
AC_CHECK_FUNCS([nanosleep usleep],break)

# Set default AM_CFLAGS for the complete project.
AM_CFLAGS=" $AM_CFLAGS "

######################################################################
# DOXYGEN SUPPORT
######################################################################

DX_HTML_FEATURE(ON)
DX_CHM_FEATURE(OFF)
DX_CHI_FEATURE(OFF)
DX_MAN_FEATURE(OFF)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(ON)
DX_PS_FEATURE(OFF)

DX_INIT_DOXYGEN([$PACKAGE_NAME],[doxygen.cfg],[doc])

##########################################################################
# debug compilation support
##########################################################################

AC_MSG_CHECKING([whether to build with debug information])
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
        [enable debug data generation (def=no)])],
    [debugit="$enableval"],
    [debugit=no])
AC_MSG_RESULT([$debugit])

if test x"$debugit" = x"yes"; then
    AC_DEFINE([DEBUG],[],[Debug Mode])
    AM_CFLAGS="$AM_CFLAGS -g -Wall -Wextra -pedantic "
    AC_SUBST(DBG_LINKOPT," ")
else
    AC_DEFINE([NDEBUG],[],[No-debug Mode])
    AM_CFLAGS="$AM_CFLAGS -Os -ffunction-sections -fdata-sections "
    AC_SUBST(DBG_LINKOPT," -Wl ")
    #AM_CPPFLAGS="$AM_CPPFLAGS -Wl --gc-sections "
fi

##########################################################################


##########################################################################
# AES Cryptographic suite compilation support
##########################################################################

AC_MSG_CHECKING([whether to build with aes cryptographic suite])
AC_ARG_ENABLE([aes],
    [AS_HELP_STRING([--enable-aes],
        [enable aes cryptographic suite computation (def=no)])],
    [aesit="$enableval"],
    [aesit=no])
AC_MSG_RESULT([$aesit])

if test x"$aesit" = x"yes"; then
    AC_DEFINE([AES],[],[Aes Mode])
    AM_CFLAGS="$AM_CFLAGS -g -Wall -Wextra -pedantic -DAESCRYPTO"
    AC_SUBST(DBG_LINKOPT," ")
fi

##########################################################################


##########################################################################
# Relay functionality in the PaC compilation support
##########################################################################

AC_MSG_CHECKING([whether to build relay functionality in the PaC])
AC_ARG_ENABLE([relay],
    [AS_HELP_STRING([--enable-relay],
        [enable relay functionality in the PaC (def=no)])],
    [relayit="$enableval"],
    [relayit=no])
AC_MSG_RESULT([$relayit])

if test x"$relayit" = x"yes"; then
    AC_DEFINE([RELAY],[],[Relay Mode])
    AM_CFLAGS="$AM_CFLAGS -g -Wall -Wextra -pedantic -DPACPRE"
    AC_SUBST(DBG_LINKOPT," ")
fi

##########################################################################

AC_SUBST([AM_CFLAGS])
# Set the preprocessor flags for the entire project
XML_FLAGS=$(xml2-config --cflags) # Adds the includes needed to build using xml2
AC_SUBST(AM_CPPFLAGS, " $AM_CPPFLAGS -L./state_machines -L./libeapstack $XML_FLAGS ")
#AC_SUBST(WPA_SRC,"");

AC_OUTPUT(Makefile src/Makefile src/libeapstack/Makefile)
