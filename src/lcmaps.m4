dnl Licensed under the Apache License, Version 2.0 (the "License");
dnl you may not use this file except in compliance with the License.
dnl You may obtain a copy of the License at
dnl 
dnl     http://www.apache.org/licenses/LICENSE-2.0
dnl 
dnl Unless required by applicable law or agreed to in writing, software
dnl distributed under the License is distributed on an "AS IS" BASIS,
dnl WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl See the License for the specific language governing permissions and
dnl limitations under the License.
dnl 
dnl Authors:
dnl 2010-
dnl     Oscar Koeroo <okoeroo@nikhef.nl>
dnl     Mischa Sall\'e <msalle@nikhef.nl>
dnl     NIKHEF Amsterdam, the Netherlands
dnl
dnl Usage: AC_LCMAPS or AC_LCMAPS([sub-component])
dnl        AC_LCMAPS_INTERFACE([interface-component])
dnl AC_LCMAPS set *_LIBS, AC_LCMAPS_INTERFACE sets *_CFLAGS

AC_DEFUN([AC_LCMAPS],
[
    dnl Make sure autoconf (bootstrap) fails when macro is undefined
    ifdef([PKG_CHECK_MODULES],
          [],
          [m4_fatal([macro PKG_CHECK_MODULES is not defined])])

    AC_REQUIRE([_AC_LCMAPS_CONFIG_FLAGS])

    AC_REQUIRE([AC_VOMS])

    dnl For lcmaps itself (not just interface) add libdir option.
    AC_ARG_WITH([lcmaps-libdir],
		[AC_HELP_STRING([--with-lcmaps-libdir=DIR],
		    [Directory where LCMAPS libraries are installed (default either LCMAPS-PREFIX/lib or LCMAPS-PREFIX/lib64)])],
		[ac_lcmaps_libdir=$withval],
		[])

    dnl Check for gsi mode
    enable_lcmaps_gsi_mode_default=yes
    AC_ARG_ENABLE([lcmaps-gsi-mode],
		  [AC_HELP_STRING([--enable-lcmaps-gsi-mode],
		    [use lcmaps flavour that provides a GSI interface (default)])],
		  [enable_lcmaps_gsi_mode=$enableval],
		  [enable_lcmaps_gsi_mode=$enable_lcmaps_gsi_mode_default])

    dnl check different modules, depending on lcmaps-gsi-mode/LCMAPS_FLAVOUR
    if test "x$enable_lcmaps_gsi_mode" = "xyes" ; then
	dnl only run GSSAPI_GSI check when we haven't done so before
	if test "x$have_globus_gssapi_gsi" = "x" ; then
	    AC_GLOBUS([GSSAPI_GSI],[],AC_MSG_WARN(["missing dependency gssapi-gsi"]))
	fi
	dnl only test lcmaps when we have globus_gssapi_gsi
	if test "x$have_globus_gssapi_gsi" = "xyes" ; then
	    LCMAPS_FLAVOUR=""
	    AC_DEFINE(LCMAPS_GSI_MODE, 1, "If defined provide the GSI interface to LCMAPS")
	    dnl Always test for basic LCMAPS
	    _AC_LCMAPS_MODULE([lcmaps])
	    dnl if $1 == lcmaps we're done
	    ifelse([$1],[lcmaps],[],[
		dnl IF we have lcmaps, now test for secondary libraries
		if test "x$have_lcmaps" = "xyes" ; then
		    dnl If an argument was given: test only that library, otherwise check all
		    ifelse([$1],[],[
			_AC_LCMAPS_MODULE([lcmaps-verify-account-from-pem])
			_AC_LCMAPS_MODULE([lcmaps-return-account-from-pem])
			_AC_LCMAPS_MODULE([lcmaps-return-poolindex])
			_AC_LCMAPS_MODULE([lcmaps-gss-assist-gridmap])
		    ],[
			_AC_LCMAPS_MODULE([$1])
		    ])
		fi
	    ])
	else
	    have_lcmaps=no
	fi
    else
	LCMAPS_FLAVOUR="_without_gsi"
	dnl Always test for basic LCMAPS-without-gsi
	_AC_LCMAPS_MODULE([lcmaps-without-gsi])
	dnl IF we have lcmaps-without-gsi, test for secondary libraries
	if test "x$have_lcmaps_without_gsi" = "xyes" ; then
	    dnl If an argument was given: test only that library, otherwise check all
	    ifelse([$1],[],[
		_AC_LCMAPS_MODULE([lcmaps-return-poolindex-without-gsi])
		_AC_LCMAPS_MODULE([lcmaps-gss-assist-gridmap-without-gsi])
	    ],[
		_AC_LCMAPS_MODULE($1-without-gsi)
	    ])
	fi
    fi
    
    AM_CONDITIONAL(LCMAPS_GSI_MODE, test x$enable_lcmaps_gsi_mode = xyes)
])

dnl Usage: AC_LCMAPS_INTERFACE([<interface-compent>],[minimal version])
dnl e.g. AC_LCMAPS_INTERFACE([globus]) or AC_LCMAPS_INTERFACE([basic],1.4.31) 
dnl $1 - type (lowercase)
dnl $2 - minimal version
AC_DEFUN([AC_LCMAPS_INTERFACE],
[
    dnl standard lcmaps configure flags
    AC_REQUIRE([_AC_LCMAPS_CONFIG_FLAGS])

    dnl Setup requested major,minor and patch
    ifelse([$2],[],
    [
	dnl in absence of version: just 0
	AC_DEFUN([_AC_LCMAPS_MAJOR],[0])
	AC_DEFUN([_AC_LCMAPS_MINOR],[0])
	AC_DEFUN([_AC_LCMAPS_PATCH],[0])
    ],[
	AC_DEFUN([_AC_LCMAPS_MAJOR],
		 [regexp([$2],[^\([0-9]+\)\(\.\([0-9]+\)\)?\(\.\([0-9]+\)\)?$],
			 [\1])])
	ifelse(_AC_LCMAPS_MAJOR,[],[
	    dnl Version is non-empty, but isn't valid
	    m4_fatal([LCMAPS_INTERFACE version $2 is not of form X[.Y[.Z]]])
	])
	dnl Now define the minor and patch version
	AC_DEFUN([_AC_LCMAPS_MINOR],
	    [regexp([$2],[^\([0-9]+\)\(\.\([0-9]+\)\)?\(\.\([0-9]+\)\)?$],
		    [ifelse([\3],[],[0],[\3])])])
	AC_DEFUN([_AC_LCMAPS_PATCH],
	    [regexp([$2],[^\([0-9]+\)\(\.\([0-9]+\)\)?\(\.\([0-9]+\)\)?$],
		    [ifelse([\5],[],[0],[\5])])])
    ])

    dnl Setup old-style header
    ifelse([$1],[basic],  [AC_DEFUN([_AC_LCMAPS_HEADER],[lcmaps_types.h])],
	   [$1],[openssl],[AC_DEFUN([_AC_LCMAPS_HEADER],[lcmaps.h])],
	   [$1],[globus], [AC_DEFUN([_AC_LCMAPS_HEADER],[lcmaps_return_poolindex.h])],
	   [$1],[],	  [AC_DEFUN([_AC_LCMAPS_HEADER],[lcmaps_return_poolindex.h])],
	   [],  [],       [m4_fatal([Unknown type $1 for AC_LCMAPS_INTERFACE])])

    dnl Check if we use old-style argument-less interface: use globus
    ifelse([$1],[],[
	dnl Old style
	m4_errprintn([WARNING: Using old-style AC_LCMAPS_INTERFACE])
	m4_errprintn([         will use AC_LCMAPS_INTERFACE(globus)])
	_AC_LCMAPS_INTERFACE([globus],[])
	dnl Set LCMAPS_INTERFACE variables for legacy support
	have_lcmaps_interface=$have_lcmaps_globus_interface
	LCMAPS_INTERFACE_CFLAGS=$LCMAPS_GLOBUS_INTERFACE_CFLAGS
	AC_SUBST(LMAPS_INTERFACE_CFLAGS)
    ],[
	dnl New style
	_AC_LCMAPS_INTERFACE([$1],[$2])
    ])
])

dnl This macro defines the --with-lcmaps-prefix and --with-lcmaps-includes
dnl options.
AC_DEFUN([_AC_LCMAPS_CONFIG_FLAGS],
[
    AC_ARG_WITH([lcmaps-prefix],
		[AC_HELP_STRING([--with-lcmaps-prefix=DIR],
		    [Prefix where LCMAPS is installed (default /usr)])],
		[ac_lcmaps_prefix=$withval],
		[ac_lcmaps_prefix=/usr])

    AC_ARG_WITH([lcmaps-includes],
		[AC_HELP_STRING([--with-lcmaps-includes=DIR],
		    [Directory where LCMAPS headers are installed (default LCMAPS-PREFIX/include)])],
		[ac_lcmaps_includes=$withval],
		[ac_lcmaps_includes=$ac_lcmaps_prefix/include])

])    

dnl This macro is the basic module checking macro: when prefix is given, test
dnl there first and if that fails test using pkg-config. Without prefix
dnl includes, the order is reversed.
dnl $1 - module
AC_DEFUN([_AC_LCMAPS_MODULE],
[
    if test "x$with_lcmaps_prefix" = "x" ; then
	PKG_CHECK_MODULES(translit($1,[a-z-],[A-Z_]), $1,
			  have_lcmaps_mod=yes, have_lcmaps_mod=no)
	if test "$have_lcmaps_mod" = "no" ; then
	    _AC_LCMAPS_DIRECT_CHECK_MODULES(translit($1,[a-z-],[A-Z_]),translit($1,[-],[_]),
					have_lcmaps_mod=yes, have_lcmaps_mod=no)
	fi
    else
	_AC_LCMAPS_DIRECT_CHECK_MODULES(translit($1,[a-z-],[A-Z_]), translit($1,[-],[_]),
				    have_lcmaps_mod=yes, have_lcmaps_mod=no)
	if test "$have_lcmaps_mod" = "no" ; then
	    PKG_CHECK_MODULES(translit($1,[a-z-],[A-Z_]), $1,
			      have_lcmaps_mod=yes, have_lcmaps_mod=no)
	fi
    fi
    [have_]translit($1,[-],[_])=$have_lcmaps_mod

    AC_SUBST(translit($1,[a-z-],[A-Z_])_LIBS)

])

AC_DEFUN([_AC_LCMAPS_DIRECT_CHECK_MODULES],
[
    ac_save_LIBS=$LIBS

    if test "x$2" != "xlcmaps" -a "x$2" != "xlcmaps_without_gsi" ; then
	ac_lcmaps_extralibs="$VOMS_CPP_LIBS -llcmaps$LCMAPS_FLAVOUR"
    else
	ac_lcmaps_extralibs="$VOMS_CPP_LIBS"
    fi

    if test "x$LCMAPS_FLAVOUR" = "x" ; then
	ac_lcmaps_extralibs="$GLOBUS_GSSAPI_GSI_NOTHR_LIBS $ac_lcmaps_extralibs"
	ac_lcmaps_extralibs="$GLOBUS_GSSAPI_GSI_LIBS $ac_lcmaps_extralibs"
	ac_lcmaps_extralibs="$GLOBUS_GSS_ASSIST_NOTHR_LIBS $ac_lcmaps_extralibs"
	ac_lcmaps_extralibs="$GLOBUS_GSS_ASSIST_LIBS $ac_lcmaps_extralibs"
	ac_lcmaps_extralibs="$GLOBUS_GSI_CERT_UTILS_NOTHR_LIBS $ac_lcmaps_extralibs"
	ac_lcmaps_extralibs="$GLOBUS_GSI_CERT_UTILS_LIBS $ac_lcmaps_extralibs"
    fi

    # check whether we have specified either lcmaps_libdir or lcmaps_prefix
    if test "x$with_lcmaps_libdir" != "x" -o "x$with_lcmaps_prefix" != "x" ; then
	# If we haven't determined a libdir, do it now from prefix
	if test "x$ac_lcmaps_libdir" = "x" ; then
	    if test "x$host_cpu" = "xx86_64" \
	     -a -e $ac_lcmaps_prefix/lib64 \
	     -a ! -h $ac_lcmaps_prefix/lib64 ; then
		ac_lcmaps_libdir="$ac_lcmaps_prefix/lib64"
	    else
		ac_lcmaps_libdir="$ac_lcmaps_prefix/lib"
	    fi
	fi

	if test "x$LCMAPS_FLAVOUR" = "x" -a "x$ac_globus_libdir" != "x" ; then
	    ac_lcmaps_libpath="$ac_globus_libdir:$ac_lcmaps_libdir"
	else
	    ac_lcmaps_libpath="$ac_lcmaps_libdir"
	fi

	ac_try_LIBS="-L$ac_lcmaps_libdir -l$2 $ac_lcmaps_extralibs"
	AC_MSG_CHECKING([for $1 at system default and $ac_lcmaps_libdir])
    else
	if test "x$LCMAPS_FLAVOUR" = "x" -a "x$ac_globus_libdir" != "x" ; then
	    ac_lcmaps_libpath="$ac_globus_libdir"
	else
	    ac_lcmas_libpath=""
	fi

	ac_try_LIBS="-l$2 $ac_lcmaps_extralibs "
	AC_MSG_CHECKING([for $1 at system default])
    fi

    if test "x$ac_lcmaps_libpath" != "x" ; then
	if test "x$LD_LIBRARY_PATH" != "x" ; then
            ac_save_LD_LIBRARY_PATH=$LD_LIBRARY_PATH
            export LD_LIBRARY_PATH="$ac_lcmaps_libpath:$LD_LIBRARY_PATH"
        else
            export LD_LIBRARY_PATH="$ac_lcmaps_libpath"
        fi

        if test "x$DYLD_LIBRARY_PATH" != "x" ; then
            ac_save_DYLD_LIBRARY_PATH=$DYLD_LIBRARY_PATH
            export DYLD_LIBRARY_PATH="$ac_lcmaps_libpath:$DYLD_LIBRARY_PATH"
        else
            export DYLD_LIBRARY_PATH="$ac_lcmaps_libpath"
        fi
    fi

    dnl We want to add the cmdline specified LIBS
    LIBS="$ac_try_LIBS $LIBS"
    AC_LINK_IFELSE([AC_LANG_SOURCE( [
		     int getMajorVersionNumber(void) { return 0; }
		     int getMinorVersionNumber(void) { return 0; }
		     int getPatchVersionNumber(void) { return 0; }
		     int main(void) {return 0;}] )],
                    [have_mod=yes], [have_mod=no])
    AC_MSG_RESULT([$have_mod])

    if test "x$have_mod" = "xyes" ; then
	[$3]
	$1_LIBS="$ac_try_LIBS"
    else
	[$4]
	$1_LIBS=""
    fi
    LIBS=$ac_save_LIBS

    if test "x$ac_save_LD_LIBRARY_PATH" = "x" ; then
	unset LD_LIBRARY_PATH
    else
	LD_LIBRARY_PATH=$ac_save_LD_LIBRARY_PATH
    fi
    if test "x$ac_save_DYLD_LIBRARY_PATH" = "x" ; then
	unset DYLD_LIBRARY_PATH
    else
	DYLD_LIBRARY_PATH=$ac_save_DYLD_LIBRARY_PATH
    fi
    if test "x$ac_save_LD_LIBRARY_PATH" = "x" ; then
        unset LD_LIBRARY_PATH
    else
        LD_LIBRARY_PATH=$ac_save_LD_LIBRARY_PATH
    fi
    if test "x$ac_save_DYLD_LIBRARY_PATH" = "x" ; then
        unset DYLD_LIBRARY_PATH
    else
        DYLD_LIBRARY_PATH=$ac_save_DYLD_LIBRARY_PATH
    fi

])

dnl This macro is the basic interface checking macro: when prefix or includes is
dnl given, test there first and if that fails test using pkg-config. Without
dnl prefix and includes, the order is reversed. When no version is given, the
dnl legacy lcmaps-interface is also tried (in the same order: direct or
dnl pkg-config).
dnl $1 - type
dnl $2 - minimum version
AC_DEFUN([_AC_LCMAPS_INTERFACE],
[
    dnl Test for GSSAPI_GSI for globus interface
    ifelse([$1],[globus],[
	dnl only run GSSAPI_GSI check when we haven't done so before
	if test "x$have_globus_gssapi_gsi" = "x" ; then
	    AC_GLOBUS([GSSAPI_GSI],[],AC_MSG_WARN(["missing dependency gssapi-gsi"]))
	fi
    ],[])
    if test "x$with_lcmaps_prefix" = "x" -a "x$with_lcmaps_includes" = "x" ; then
	dnl test lcmaps-<type>-interface first, when no version: then lcmaps-interface
	PKG_CHECK_MODULES([LCMAPS_]translit($1,[a-z],[A-Z])[_INTERFACE],
	    [lcmaps-$1-interface ifelse([$2],[],[],[>= $2])],
	    [have_lcmaps_$1_interface=yes], [have_lcmaps_$1_interface=no])
	if test "x$have_lcmaps_$1_interface" = "xno" ; then
	    _AC_LCMAPS_DIRECT_CHECK_INTERFACE([LCMAPS_]translit($1,[a-z],[A-Z])[_INTERFACE], [lcmaps_$1.h],
		[have_lcmaps_$1_interface=yes], [have_lcmaps_$1_interface=no])
	    ifelse([$2],[],[
		if test "x$have_lcmaps_$1_interface" = "xno" ; then
		    dnl test old-style lcmaps-interface
		    PKG_CHECK_MODULES([LCMAPS_INTERFACE], [lcmaps-interface < 1.4.31],
			[have_lcmaps_$1_interface=yes], [have_lcmaps_$1_interface=no])
		    if test "x$have_lcmaps_$1_interface" = "xno" ; then
			_AC_LCMAPS_DIRECT_CHECK_INTERFACE([LCMAPS_INTERFACE], _AC_LCMAPS_HEADER,
			    [have_lcmaps_$1_interface=yes], [have_lcmaps_$1_interface=no])
		    fi
		    [LCMAPS_]translit($1,[a-z],[A-Z])[_INTERFACE_CFLAGS]=$LCMAPS_INTERFACE_CFLAGS
		fi
	    ],[])
	fi
    else
	dnl test lcmaps-<type>-interface first, when no version: then lcmaps-interface
	_AC_LCMAPS_DIRECT_CHECK_INTERFACE([LCMAPS_]translit($1,[a-z],[A-Z])[_INTERFACE], [lcmaps_$1.h],
	    [have_lcmaps_$1_interface=yes], [have_lcmaps_$1_interface=no])
	if test "x$have_lcmaps_$1_interface" = "xno" ; then
	    PKG_CHECK_MODULES([LCMAPS_]translit($1,[a-z],[A-Z])[_INTERFACE],
		[lcmaps-$1-interface ifelse([$2],[],[],[>= $2])],
		[have_lcmaps_$1_interface=yes], [have_lcmaps_$1_interface=no])
	    ifelse([$2],[],[
		if test "x$have_lcmaps_$1_interface" = "xno" ; then
		    dnl test old-style lcmaps-interface
		    _AC_LCMAPS_DIRECT_CHECK_INTERFACE([LCMAPS_INTERFACE], _AC_LCMAPS_HEADER,
			[have_lcmaps_$1_interface=yes], [have_lcmaps_$1_interface=no])
		    if test "x$have_lcmaps_$1_interface" = "xno" ; then
			PKG_CHECK_MODULES([LCMAPS_INTERFACE], [lcmaps-interface < 1.4.31],
			    [have_lcmaps_$1_interface=yes], [have_lcmaps_$1_interface=no])
		    fi
		    [LCMAPS_]translit($1,[a-z],[A-Z])[_INTERFACE_CFLAGS]=$LCMAPS_INTERFACE_CFLAGS
		fi
	    ],[])
	fi
    fi
    LCMAPS_CFLAGS=[$LCMAPS_]translit($1,[a-z],[A-Z])[_INTERFACE_CFLAGS]
    AC_SUBST([LCMAPS_]translit($1,[a-z],[A-Z])[_INTERFACE_CFLAGS])
    AC_SUBST(LCMAPS_CFLAGS)
])

dnl $1 - full interface name
dnl $2 - header to test
AC_DEFUN([_AC_LCMAPS_DIRECT_CHECK_INTERFACE],
[
    ac_save_CFLAGS=$CFLAGS

    if test "x$ac_lcmaps_includes" != "x" ; then
	ac_try_CFLAGS="-I$ac_lcmaps_includes"
	AC_MSG_CHECKING(for $1 ($2) at system default and $ac_lcmaps_includes)
    else
	AC_MSG_CHECKING(for $1 ($2) at system default)
    fi

    dnl We want to add the cmdline specified CFLAGS, but only for dnl checking,
    dnl not to the *_CFLAGS.
    CFLAGS="$ac_try_CFLAGS $CFLAGS"

    dnl Wether we check for old or new-style
    ifelse([$1],[LCMAPS_INTERFACE],[
	dnl Test we *don't* have the new interface
	AC_COMPILE_IFELSE([AC_LANG_SOURCE( [#include <lcmaps/lcmaps_version.h>
	    int main(void) {return 0;} ] )],
	    [	dnl We have the new-style interface and 
		dnl should NOT have tested LCMAPS_INTERFACE
		have_mod=no
	    ],[ dnl Test we have the old interface
		ifelse([$2],[lcmaps_return_poolindex.h],[
		    CFLAGS="$GLOBUS_GSSAPI_CFLAGS $GLOBUS_GSSAPI_GSI_NOTHR_CFLAGS $CFLAGS"
		],[])
		AC_COMPILE_IFELSE([AC_LANG_SOURCE( [#include <lcmaps/$2>
				    int main(void) {return 0;} ] )],
				    [have_mod=yes], [have_mod=no])
	    ])
	AC_MSG_RESULT([$have_mod])
    ],[
	dnl New style test
	ifelse([$2],[lcmaps_globus.h],[
	    CFLAGS="$GLOBUS_GSSAPI_CFLAGS $GLOBUS_GSSAPI_GSI_NOTHR_CFLAGS $CFLAGS"
	],[])
	AC_COMPILE_IFELSE([AC_LANG_SOURCE( [#include <lcmaps/$2>
#ifndef LCMAPS_API_MAJOR_VERSION
#error LCMAPS API version is undefined, this should not happen for new-style interface
#endif
#if (LCMAPS_API_MAJOR_VERSION) < (]_AC_LCMAPS_MAJOR[) || \
	( (LCMAPS_API_MAJOR_VERSION) == (]_AC_LCMAPS_MAJOR[) && \
	  ( (LCMAPS_API_MINOR_VERSION) < (]_AC_LCMAPS_MINOR[) || \
	    ( (LCMAPS_API_MINOR_VERSION) == (]_AC_LCMAPS_MINOR[) && \
	      (LCMAPS_API_PATCH_VERSION) < (]_AC_LCMAPS_PATCH[) ) ) )
#error LCMAPS API version older than ]_AC_LCMAPS_MAJOR[.]_AC_LCMAPS_MINOR[.]_AC_LCMAPS_PATCH[
#endif
			    int main(void) {return 0;} ] )],
			    [have_mod=yes], [have_mod=no])
	AC_MSG_RESULT([$have_mod])
    ])

    if test "x$have_mod" = "xyes" ; then
	[$3]
	$1_CFLAGS=$ac_try_CFLAGS
    else
	[$4]
	$1_CFLAGS=""
    fi

    CFLAGS=$ac_save_CFLAGS
    
])

