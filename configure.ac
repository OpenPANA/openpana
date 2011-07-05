
AC_PREREQ([2.65])
AC_INIT([OpenPANA], [0.1], [openpana-users@lists.sourceforge.net])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE()
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC_C99
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lbfd':
AC_CHECK_LIB([bfd], [main])
# FIXME: Replace `main' with a function in `-lcrypt32':
AC_CHECK_LIB([crypt32], [main])
# FIXME: Replace `main' with a function in `-lcrypto':
AC_CHECK_LIB([crypto], [main])
# FIXME: Replace `main' with a function in `-ldl':
AC_CHECK_LIB([dl], [main])
# FIXME: Replace `main' with a function in `-ldnet':
AC_CHECK_LIB([dnet], [main])
# FIXME: Replace `main' with a function in `-leap':
#AC_CHECK_LIB([eap], [main])
# FIXME: Replace `main' with a function in `-lgcrypt':
AC_CHECK_LIB([gcrypt], [main])
# FIXME: Replace `main' with a function in `-lgdi32':
AC_CHECK_LIB([gdi32], [main])
# FIXME: Replace `main' with a function in `-lgnutls':
AC_CHECK_LIB([gnutls], [main])
# FIXME: Replace `main' with a function in `-lncurses':
AC_CHECK_LIB([ncurses], [main])
# FIXME: Replace `main' with a function in `-lnss3':
AC_CHECK_LIB([nss3], [main])
# FIXME: Replace `main' with a function in `-lole32':
AC_CHECK_LIB([ole32], [main])
# FIXME: Replace `main' with a function in `-loleaut32':
AC_CHECK_LIB([oleaut32], [main])
# FIXME: Replace `main' with a function in `-lpacket':
AC_CHECK_LIB([packet], [main])
# FIXME: Replace `main' with a function in `-lpcap':
AC_CHECK_LIB([pcap], [main])
# FIXME: Replace `main' with a function in `-lpcsclite':
AC_CHECK_LIB([pcsclite], [main])
AC_CHECK_LIB([pthread], [pthread_mutex_lock])
# FIXME: Replace `main' with a function in `-lreadline':
AC_CHECK_LIB([readline], [main])
# FIXME: Replace `main' with a function in `-lssl':
AC_CHECK_LIB([ssl], [main])
# FIXME: Replace `main' with a function in `-lssl':
AC_CHECK_LIB([xml2], [main])
# FIXME: Replace `main' with a function in `-lssl':
AC_CHECK_LIB([xslt], [main])
# FIXME: Replace `main' with a function in `-lssl':
AC_CHECK_LIB([exslt], [main])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_CHECK_FUNCS([alarm dup2 getcwd gettimeofday inet_ntoa memmove memset mkdir rmdir select setenv socket strchr strdup strerror strspn strstr strtol strtoul])

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

DX_INIT_DOXYGEN([$PACKAGE_NAME],[doxygen.cfg],[documentation])

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
    AM_CFLAGS="$AM_CFLAGS -g -Wall -Wextra -pedantic -O0 -D DEBUG"
else
    AC_DEFINE([NDEBUG],[],[No-debug Mode])
    AM_CFLAGS="$AM_CFLAGS -O2"
fi

##########################################################################

AC_SUBST([AM_CFLAGS])
# Set the preprocessor flags for the entire project
AC_SUBST(AM_CPPFLAGS, " -L./state_machines -L./libeapstack -I./wpa_supplicant/src -I./wpa_supplicant/src/utils  -I./wpa_supplicant/src -I./wpa_supplicant/src/utils")

##To include empty targets on libeapstack, in order to allow distribution
AC_CONFIG_FILES(src/libeapstack/Makefile)

AC_OUTPUT(Makefile src/Makefile)
