 ###############################################################
 # 
 # Copyright 2011 University of Nebraska-Lincoln.
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

#######################################################################
##
## Makefile.am for lcmaps-plugins-mount-under-scratch
##
#######################################################################

ACLOCAL_AMFLAGS = -I src

# no-write-strings is done because lcmaps_log uses "char *" instead
# of "const char *", causing newer compilers to freak
AM_CFLAGS = \
        -Werror \
	-Wall \
	-Wp,-D_FORTIFY_SOURCE=2 \
        $(LCMAPS_CFLAGS)

AM_CXXFLAGS = \
        $(LCMAPS_CFLAGS) \
        -Wno-write-strings \
        -Werror \
	-Wall \
	-Wp,-D_FORTIFY_SOURCE=2 \
        $(CXX0X_CFLAGS)

EXTRA_DIST = bootstrap lcmaps-plugins-static-mapping.spec

plugindir = $(MODULEDIR)
plugin_LTLIBRARIES = \
        liblcmaps_static_mapping.la

liblcmaps_static_mapping_la_SOURCES = \
	src/lcmaps_static_mapping.c \
	src/proc_info.h \
	src/proc_info.c \
	src/static_mapping.cpp \
	src/static_mapping.h

liblcmaps_static_mapping_la_LDFLAGS = -avoid-version

gridsecdir = $(sysconfdir)/grid-security
dist_gridsec_DATA = glexec-mapfile

install-data-hook:
	( \
	cd $(DESTDIR)$(plugindir); \
	for mod in static_mapping ; do \
	    rm -f lcmaps_$$mod.mod; \
	    ln -s liblcmaps_$$mod.so.0.0.0 lcmaps_$$mod.mod; \
	done \
	)

