AM_CPPFLAGS+= -D CONFIGDIR=\"$(sysconfdir)\" ## Sets the config dir
## wpa_supplicant source directory
WPA_SRC =$(srcdir)/wpa_supplicant/src
INCLUDES		      = -I$(WPA_SRC) -I$(WPA_SRC)/utils

### user programs ###
bin_PROGRAMS = openpaa openpac

### source declarations ###
openpaa_SOURCES               =	state_machines/session.c \
				state_machines/statemachine.c \
				state_machines/paamachine.c \
				prf_plus.c \
				panamessages.c \
				lalarm.c \
				panautils.c \
				mainservidor.c \
				loadconfig.c \
				aes.c \
				cmac.c
openpaa_CPPFLAGS 	      = $(AM_CPPFLAGS) 
openpaa_CFLAGS		      = $(AM_CFLAGS) -DISSERVER
openpaa_LDFLAGS		      = $(DBG_LINKOPT)

### library dependencies ###

openpaa_LDADD                     = libeapstack/libeap.a


### source declarations ###

openpac_SOURCES               =	state_machines/session.c \
				state_machines/statemachine.c \
				state_machines/pacmachine.c \
				prf_plus.c \
				panamessages.c \
				lalarm.c \
				panautils.c \
				maincliente.c \
				loadconfig.c \
				aes.c \
				cmac.c
openpac_CPPFLAGS 	      = $(AM_CPPFLAGS) 
openpac_CFLAGS		      = $(AM_CFLAGS) -DISCLIENT
openpac_LDFLAGS		      = $(DBG_LINKOPT)
### library dependencies ###

openpac_LDADD                     = libeapstack/libeap.a

## Adding PANA header files to distribute using "make dist"
EXTRA_DIST =  *.h state_machines/*.h config.xml dtd.xml

## Extra config files needed
sysconf_DATA = \
		config.xml \
		dtd.xml

