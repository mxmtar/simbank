
ACLOCAL_AMFLAGS = -I m4 --install

bin_PROGRAMS = sbg4

sbg4_CFLAGS = $(AM_CFLAGS) -Wall
sbg4_LDFLAGS = $(AM_LDFLAGS) -lrt

sbg4_SOURCES = \
		sbg4.c \
		iso_iec_7816.c

include_HEADERS = \
		iso_iec_7816.h \
		ss9006.h \
		simcard-def.h \
		x_timer.h

CLEANFILES = *~
