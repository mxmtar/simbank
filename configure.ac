#
# Process this file with autoconf to produce a configure script.
#
AC_PREREQ([2.60])

# set project attribute
AC_INIT([simbank], [0.6])

# init automake
AM_INIT_AUTOMAKE([-Wall -Werror])

m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

# generating version string
if test -f version ; then
	PACKAGE_VERSION=`cat version`
fi

# construct package string
PACKAGE_STRING=${PACKAGE_NAME}-${PACKAGE_VERSION}

AC_CANONICAL_BUILD
AC_CANONICAL_HOST

AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_SRCDIR([simbank.c])

AC_COPYRIGHT("Polygator")
AC_REVISION(0.6)

# prepare autoconfig header data
AC_CONFIG_HEADER([autoconfig.h])

# manage platform values
BUILD_PLATFORM=${build}
BUILD_CPU=${build_cpu}
BUILD_VENDOR=${build_vendor}
BUILD_OS=${build_os}

AC_SUBST(BUILD_PLATFORM)
AC_SUBST(BUILD_CPU)
AC_SUBST(BUILD_VENDOR)
AC_SUBST(BUILD_OS)

HOST_PLATFORM=${host}
HOST_CPU=${host_cpu}
HOST_VENDOR=${host_vendor}
HOST_OS=${host_os}

AC_SUBST(HOST_PLATFORM)
AC_SUBST(HOST_CPU)
AC_SUBST(HOST_VENDOR)
AC_SUBST(HOST_OS)

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CXX
AC_PROG_GREP
AC_PROG_INSTALL
AC_PROG_SED
AC_PROG_LIBTOOL

m4_ifdef([AM_PROG_CC_C_O], [AM_PROG_CC_C_O])

# Checks for packages.
# Checks for required simbank-linux version.
PG_SIMBANK_LINUX_VERSION_PREREQ([0.1])

# Checks for header files.
AC_CHECK_HEADER([simbank/version.h], [], [echo "Simbank kernel module not installed" ; exit 1])
AC_CHECK_HEADER([simbank/simcard-def.h], [], [echo "Simbank kernel module not installed" ; exit 1])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT

AC_MSG_NOTICE(Package "$PACKAGE_STRING")
AC_MSG_NOTICE( Build on:)
AC_MSG_NOTICE(  OS: $build_os)
AC_MSG_NOTICE(  Vendor: $build_vendor)
AC_MSG_NOTICE(  CPU: $build_cpu)
AC_MSG_NOTICE( Build for: OS:)
AC_MSG_NOTICE(  OS: $host_os)
AC_MSG_NOTICE(  Vendor: $host_vendor)
AC_MSG_NOTICE(  CPU: $host_cpu)
if test "${cross_compiling}" = "yes"; then
	AC_MSG_NOTICE(Cross compilation needed)
fi
