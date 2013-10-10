#
# check simbank-linux version
#
# PG_SIMBANK_LINUX_VERSION_PREREQ([version])

AC_DEFUN([PG_SIMBANK_LINUX_VERSION_PREREQ],
[

AC_MSG_CHECKING([for simbank-linux version >= $1])

SIMBANK_LINUX_VERSION=""

if test -f "$lt_sysroot/usr/include/simbank/version.h" ; then
	REQ_SIMBANK_LINUX_VERSION=$1
	[REQ_SIMBANK_LINUX_VERSION_TRIM=`LANG=C printf "$REQ_SIMBANK_LINUX_VERSION" | ${GREP} -e '^[0-9]\{1,2\}\.[0-9]\{1,2\}' | ${SED} -e '{s:\(^[0-9]\{1,2\}\.[0-9]\{1,2\}\)\(.*\):\1:}'`]
	if test -z "$REQ_SIMBANK_LINUX_VERSION_TRIM"; then
		AC_MSG_RESULT(fail)
		AC_MSG_RESULT(bad version string \"$1\")
		exit 1
	fi
	REQ_SIMBANK_LINUX_VERSION_PARTS=`LANG=C printf "$REQ_SIMBANK_LINUX_VERSION_TRIM" | ${SED} -e 'y:\.: :'`
	COUNT="0"
	REQ_SIMBANK_LINUX_VERSION_BIN=`
	for PARTS in $REQ_SIMBANK_LINUX_VERSION_PARTS ; do
		if ((COUNT)) ; then
			printf "%02d" $PARTS
		else
			printf "%d" $PARTS
		fi
		let COUNT++;
	done`


	[TST_SIMBANK_LINUX_VERSION=`cat $lt_sysroot/usr/include/simbank/version.h | ${GREP} -e '[[:space:]]*#define[[:space:]]*SIMBANK_LINUX_VERSION[[:space:]]*\"[0-9]\{1,2\}\.[0-9]\{1,2\}.*\".*' | ${SED} -e '{s:[[:space:]]*#define[[:space:]]*SIMBANK_LINUX_VERSION[[:space:]]*\"\([0-9]\{1,2\}\.[0-9]\{1,2\}\).*\".*:\1:}'`]
	if test "$TST_SIMBANK_LINUX_VERSION" = ""; then
		AC_MSG_RESULT(fail)
		AC_MSG_RESULT([Cannot find SIMBANK_LINUX_VERSION in simbank/version.h header to retrieve simbank-linux version!])
		exit 1
	fi
	SIMBANK_LINUX_VERSION=TST_SIMBANK_LINUX_VERSION

	[TST_SIMBANK_LINUX_VERSION_TRIM=`LANG=C printf "$TST_SIMBANK_LINUX_VERSION" | ${GREP} -e '^[0-9]\{1,2\}\.[0-9]\{1,2\}' | ${SED} -e '{s:\(^[0-9]\{1,2\}\.[0-9]\{1,2\}\)\(.*\):\1:}'`]
	if test -z "$TST_SIMBANK_LINUX_VERSION_TRIM"; then
		AC_MSG_RESULT(fail)
		AC_MSG_RESULT(bad version string \"$TST_SIMBANK_LINUX_VERSION_TRIM\")
		exit 1
	fi
	TST_SIMBANK_LINUX_VERSION_PARTS=`LANG=C printf "$TST_SIMBANK_LINUX_VERSION_TRIM" | ${SED} -e 'y:\.: :'`
	COUNT="0"
	TST_SIMBANK_LINUX_VERSION_BIN=`
	for PARTS in $TST_SIMBANK_LINUX_VERSION_PARTS ; do
		if ((COUNT)) ; then
			printf "%02d" $PARTS
		else
			printf "%d" $PARTS
		fi
		let COUNT++;
	done`

	if test $TST_SIMBANK_LINUX_VERSION_BIN -ge $REQ_SIMBANK_LINUX_VERSION_BIN ; then
		AC_SUBST(SIMBANK_LINUX_VERSION)
		AC_MSG_RESULT($TST_SIMBANK_LINUX_VERSION)
	else
		AC_MSG_RESULT(fail)
		AC_MSG_RESULT(simbank-linux version \"$TST_SIMBANK_LINUX_VERSION\" is early then required \"$REQ_SIMBANK_LINUX_VERSION\")
		exit 1
	fi
else
	AC_MSG_RESULT(fail)
	AC_MSG_RESULT(simbank/version.h not found")
	exit 1
fi

])
