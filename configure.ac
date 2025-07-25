##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2018 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
#                                              -*- Autoconf -*-
# Process this file with autoconf to produce configure script.
#

AC_PREREQ([2.65])
AC_INIT([tr181], [1.0], [BUG-REPORT-ADDRESS])
AM_INIT_AUTOMAKE([foreign])
LT_INIT

AC_ARG_ENABLE([unitTestDockerSupport],
             AS_HELP_STRING([--enable-unitTestDockerSupport],[enable Docker support for unit testing (default is no)]),
             [
               case "${enableval}" in
                yes) 
		     UNIT_TEST_DOCKER_SUPPORT=true
                     m4_if(m4_sysval,[0],[AC_CONFIG_FILES([source/test/Makefile])]);;
                no)
                     UNIT_TEST_DOCKER_SUPPORT=false 
		     AC_MSG_WARN([Docker support is disabled]);;
                 *) 
	           AC_MSG_ERROR([bad value ${enableval} for --enable-unitTestDockerSupport ])
		   ;;
               esac
             ],
             [AC_MSG_WARN([Docker support is disabled])])
AM_CONDITIONAL([UNIT_TEST_DOCKER_SUPPORT], [test x$UNIT_TEST_DOCKER_SUPPORT = xtrue])
AC_SUBST([UNIT_TEST_DOCKER_SUPPORT])

FEATURE_WAN_FAIL_OVER=no
AC_ARG_ENABLE([wanfailover],
        AS_HELP_STRING([--enable-wanfailover],[enable wanfailover]),
        [
          case "${enableval}" in
           yes) FEATURE_WAN_FAIL_OVER=yes ;;
           no) AC_MSG_ERROR([wanfailover is disabled]) ;;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-wanfailover ]) ;;
           esac
           ],
         [echo "wanfailover is disabled."])

AM_CONDITIONAL([FEATURE_WAN_FAIL_OVER], [test $FEATURE_WAN_FAIL_OVER = yes])

# Checks for Core net lib Feature Support
AC_ARG_ENABLE([core_net_lib_feature_support],
[  --enable-core_net_lib_feature_support=val Turn on core_net_lib Feature, val=true or false],
[case "${enableval}" in
  yes) core_net_lib_feature_support=true ;;
  no)  core_net_lib_feature_support=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-core_net_lib_feature_support]) ;;
esac],[core_net_lib_feature_support=false])
AM_CONDITIONAL(CORE_NET_LIB_FEATURE_SUPPORT, test x"$core_net_lib_feature_support" = x"true")

AC_PREFIX_DEFAULT(`pwd`)
AC_ENABLE_SHARED
AC_DISABLE_STATIC

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AM_PROG_CC_C_O
AM_PROG_LIBTOOL(libtool)

SYSTEMD_CFLAGS=" "
SYSTEMD_LDFLAGS=" "
AC_ARG_ENABLE([notify],
	AS_HELP_STRING([--enable-notify],[enable systemd notify]),
	[
	  case "${enableval}" in
  	   yes) SYSTEMD_CFLAGS="-DENABLE_SD_NOTIFY"
                SYSTEMD_LDFLAGS="-lsystemd" ;;
           no) AC_MSG_ERROR([systemd notify is disabled]) ;;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-notify ]) ;;
           esac
           ],
	 [echo "headless build is enable"])

NONROOT_CFLAGS=" "
AC_ARG_ENABLE([dropearly],
        AS_HELP_STRING([--enable-dropearly],[enable dropearly]),
        [
          case "${enableval}" in
           yes) NONROOT_CFLAGS="-DDROP_ROOT_EARLY" ;;
            no) AC_MSG_NOTICE([dropearly is disabled]) ;;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-dropearly ]) ;;
           esac
           ],
         [echo "dropearly is enable"])

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE

# Checks for library functions.
AC_FUNC_MALLOC

AC_SUBST(SYSTEMD_CFLAGS)
AC_SUBST(SYSTEMD_LDFLAGS)
AC_SUBST(NONROOT_CFLAGS)

AC_CONFIG_FILES(
	source/TR-181/board_sbapi/Makefile
	source/TR-181/middle_layer_src/Makefile
	source/TR-181/Makefile
	source/Makefile
	source/EthSsp/Makefile
        Makefile
)

AC_OUTPUT
