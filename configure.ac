 ###############################################################
 # 
 # Copyright 2011 University of Nebraska, Lincoln.
 # 
 # Licensed under the Apache License, Version 2.0 (the "License"); you 
 # may not use this file except in compliance with the License.  You may 
 # obtain a copy of the License at 
 # 
 #    http://www.apache.org/licenses/LICENSE-2.0 
 # 
 # Unless required by applicable law or agreed to in writing, software 
 # distributed under the License is distributed on an "AS IS" BASIS, 
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and 
 # limitations under the License. 
 # 
 ############################################################### 

AC_INIT(lcmaps-plugins-static-mapping,0.0.1,bbockelm@cse.unl.edu)
AC_PREREQ(2.57)
AM_INIT_AUTOMAKE([1.9 no-define foreign])
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_LIBTOOL
AC_PROG_CC
AC_PROG_CXX

# Check LCMAPS location
AC_LCMAPS_INTERFACE([basic])
if test "x$have_lcmaps_interface" = "xno" ; then
    AC_MSG_FAILURE(["no LCMAPS interface found"])
fi

dnl allow the setting of a different path for the plug-ins
dnl Makefiles should set the plugindir to $MODULEDIR.
AC_ARG_WITH([moduledir],
  [AS_HELP_STRING([--with-moduledir=path],
    [Specify the install location of the plug-ins])],
[
	AC_SUBST([MODULEDIR], [$withval])
],
[
	AC_SUBST([MODULEDIR], ['${libdir}/lcmaps'])
])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

