# main init. (PROJECT NAME), (VERSION), (DEBUG EMAIL ADDR)
AC_INIT([libid2], [1.1], [chia_jason96@live.com])

# initialize automake, report warnings as errors
# foreign keyword here specify that this package is a foreign package
AM_INIT_AUTOMAKE([foreign -Wall -Werror subdir-objects])

# initialize libtool (for shared library)
AM_PROG_AR
LT_INIT

# check for C and C++ compiler
AC_PROG_CC
AC_PROG_CXX

# when we are compiling libraries (static)
# rendered obsolete by LT_INIT
#AC_PROG_RANLIB

# specify the header
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

# all makefiles (makefile.am) must be declared here. one .am per directory
AC_CONFIG_FILES([makefile src/makefile])

AC_DEFINE([EWLOG], [1], [Enable warning and error logs]) # enable warning and error logs

# Argument to enable error/warning log, defaults to YES
AC_ARG_ENABLE([ewlog],
[  --enable-ewlog    'Enable error and warning output to stdout'],
[case "${enableval}" in
  yes) ewlog=true ;;
  no)  ewlog=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-ewlog]) ;;
esac],[ewlog=true])
AS_IF(
[test x$ewlog = xtrue],[AC_DEFINE([EWLOG],[1],['Error and warning logs enabled'])]
)

# Argument to enable debug log, defaults to NO
AC_ARG_ENABLE([debug],
[  --enable-debug    'Enable debugging output to stdout'],
[case "${enableval}" in
  yes) debug=true ;;
  no)  debug=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
esac],[debug=false])
AS_IF(
[test x$debug = xtrue],[AC_DEFINE([DEBUG],[1],['Debugging output enabled'])]
)

# Argument to compile test programs, defaults to NO
AC_ARG_ENABLE([tests],
[  --enable-tests    'Compile test programs'],
[case "${enableval}" in
  yes) tests=true ;;
  no)  tests=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-tests]) ;;
esac],[tests=false])
AM_CONDITIONAL([COMPILETESTS], [test x$tests = xtrue])

# Specify the crypto lib, i.e. --enable-cryptlib=sodium
# default to libsodium
AC_ARG_ENABLE([ecurve],
[  --enable-ecurve 	'Specify which ec operations to use (ristretto255, ed25519)'],
[ecurve=$enableval],
[ecurve='ristretto255'])
AS_IF(
[test x$ecurve = x'ristretto255'],[AC_DEFINE([URT25519],[1],['Using ristretto255'])]
)
AS_IF(
[test x$ecurve = x'ed25519'],[AC_DEFINE([UED25519],[1],['Using ed25519'])]
)

AC_OUTPUT
