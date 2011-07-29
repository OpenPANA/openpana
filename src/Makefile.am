#ACLOCAL_AMFLAGS  = -I m4

#SUBDIRS = state_machines

#HIPL_HEADER_LOCATIONS = firewall/*.h hipd/*.h lib/*/*.h modules/*/*/*.h test/*/*.h test/*/*/*.h
#HIPL_HEADER_LIST = $(wildcard $(addprefix $(srcdir)/,$(HIPL_HEADER_LOCATIONS)))

### user programs ###
bin_PROGRAMS = PAA PaC

### source declarations ###

PAA_SOURCES               =	state_machines/session.c \
				state_machines/statemachine.c \
				state_machines/paamachine.c \
				prf_plus.c \
				panamessages.c \
				lalarm.c \
				panautils.c \
				mainservidor.c \
				loadconfig.c
PAA_CPPFLAGS =		$(AM_CPPFLAGS) -D DATADIR=\"$(datadir)/@PACKAGE@\" -D ISSERVER

### library dependencies ###

PAA_LDADD                     = libeapstack/libeap.a


### source declarations ###

PaC_SOURCES               =	state_machines/session.c \
				state_machines/statemachine.c \
				state_machines/pacmachine.c \
				prf_plus.c \
				panamessages.c \
				lalarm.c \
				panautils.c \
				maincliente.c \
				loadconfig.c
PaC_CPPFLAGS =		$(AM_CPPFLAGS) -D DATADIR=\"$(datadir)/@PACKAGE@\" -D ISCLIENT

### library dependencies ###

PaC_LDADD                     = libeapstack/libeap.a

# Adding PANA header files to distribute using "make dist"
EXTRA_DIST =  *.h state_machines/*.h config.xml dtd.xml

# Extra config files needed
PaCextradir = $(datadir)/@PACKAGE@
PaCextra_DATA = \
		config.xml \
		dtd.xml

