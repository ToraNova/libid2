# main init. (PROJECT NAME), (VERSION), (DEBUG EMAIL ADDR)
AC_INIT([template-autoc], [1.0], [chia_jason96@live.com])

# initialize automake, report warnings as errors
# foreign keyword here specify that this package is a foreign package
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

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

AC_DEFINE([EWLOG], [0], [Enable warning and error logs]) # enable warning and error logs

AC_OUTPUT
