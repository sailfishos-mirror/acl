# Copyright (C) 2009  Andreas Gruenbacher <agruen@suse.de>
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

AC_PREREQ([2.69])
AC_INIT([acl], [2.4.0], [acl-devel@nongnu.org])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([include/config.h])
AC_PREFIX_DEFAULT(/usr)

AM_INIT_AUTOMAKE([-Wall foreign 1.15 dist-xz subdir-objects])
AM_SILENT_RULES([yes])

AC_PROG_CC
AM_PROG_CC_C_O
AC_USE_SYSTEM_EXTENSIONS
AC_FUNC_GCC_VISIBILITY
AC_C_BIGENDIAN
AC_SYS_LARGEFILE

AM_PROG_AR
LT_INIT

AC_CHECK_FUNCS(openat2)
AC_CHECK_HEADERS([linux/openat2.h])
AC_CHECK_DECL([__NR_openat2], [], [], [[#include <sys/syscall.h>]])
if test "x$ac_cv_have_decl___NR_openat2" = xyes -a \
	"x$ac_cv_header_linux_openat2_h" = xyes; then
	use_openat2=yes
else
	use_openat2=no
fi
AM_CONDITIONAL([USE_OPENAT2], [test "x$use_openat2" = xyes])
AM_CONDITIONAL([HAVE_OPENAT2], [test "x$ac_cv_func_openat2" = xyes])
AS_IF([test "x$use_openat2" = xyes],
      [AC_DEFINE([USE_OPENAT2], [1], [Define to use openat2 syscall])])

AC_ARG_ENABLE([unsafe-restore-warnings],
	[AS_HELP_STRING([--disable-unsafe-restore-warnings], [Disable warnings about unsafe restore operations])])
if test "x$use_openat2" = xno; then
	enable_unsafe_restore_warnings=no
fi
AM_CONDITIONAL([UNSAFE_RESTORE_WARNINGS], [test "x$enable_unsafe_restore_warnings" != xno])
AS_IF([test "x$enable_unsafe_restore_warnings" != xno],
      [AC_DEFINE([UNSAFE_RESTORE_WARNINGS], [1], [Define to enable unsafe restore warnings])])

AC_CHECK_FUNCS(getxattrat setxattrat listxattrat removexattrat)
AM_CONDITIONAL([NEED_XATTRAT],
	       [test "x$ac_cv_func_getxattrat" = xno -o \
		     "x$ac_cv_func_setxattrat" = xno -o \
		     "x$ac_cv_func_listxattrat" = xno -o \
		     "x$ac_cv_func_removexattrat" = xno])

dnl Minimal version supporting AM_GNU_GETTEXT_REQUIRE_VERSION.
AM_GNU_GETTEXT_VERSION([0.19.6])
dnl Require at least the following version, but use the latest available one.
AM_GNU_GETTEXT_REQUIRE_VERSION([0.19.8])
AM_GNU_GETTEXT([external])

AC_ARG_ENABLE([debug],
	[AS_HELP_STRING([--enable-debug], [Enable extra debugging])])
AS_IF([test "x$enable_debug" = "xyes"],
	[CPPFLAGS="$CPPFLAGS -DDEBUG"],
	[CPPFLAGS="$CPPFLAGS -DNDEBUG"])

dnl Automatically increment the revision for every release.
set -- $(IFS=.; echo ${PACKAGE_VERSION})
AS_IF([test $# -ne 3 -o ${#1} -gt 1 -o ${#2} -gt 1 -o ${#3} -gt 2],
	[AC_MSG_ERROR([This PACKAGE_VERSION breaks LT_REVISION])])
LT_REVISION=$(printf "%d%d%02d" "$1" "$2" "$3")
AC_SUBST(LT_REVISION)

AC_PACKAGE_NEED_ATTR_ERROR_H

AC_CONFIG_COMMANDS([include/acl],
	[dnl
	rm -rf include/acl
	$as_ln_s "$ac_abs_top_srcdir/include" include/acl
	])
AC_CONFIG_COMMANDS([include/sys],
	[dnl
	rm -rf include/sys
	$as_ln_s "$ac_abs_top_srcdir/include" include/sys
	])
AC_CONFIG_FILES([
	libacl.pc
	Makefile
	po/Makefile.in
])
AC_OUTPUT
