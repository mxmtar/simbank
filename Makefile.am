
ACLOCAL_AMFLAGS = -I m4 --install

dist_sysconf_DATA = simbank.conf

dist_bin_SCRIPTS = simbankctl

bin_PROGRAMS = simbank

simbank_CFLAGS = $(AM_CFLAGS) -Wall
simbank_LDFLAGS = $(AM_LDFLAGS) -lrt

simbank_SOURCES = \
		simbank.c \
		iso_iec_7816.c \
		3gpp_ts_11_11.c \
		3gpp_ts_23_038.c \
		3gpp_ts_101_221.c

noinst_HEADERS = \
		iso_iec_7816.h \
		3gpp_ts_11_11.h \
		3gpp_ts_23_038.h \
		3gpp_ts_101_221.h \
		ss9006.h \
		simcard-def.h \
		x_timer.h

CLEANFILES = *~

EXTRA_DIST = simbank.init
