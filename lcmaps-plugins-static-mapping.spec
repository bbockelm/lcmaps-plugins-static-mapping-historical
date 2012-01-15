Summary: LCMAPS plugin for a static mapfile
Name: lcmaps-plugins-static-mapping
Version: 0.0.1
Release: 1%{?dist}
License: Public Domain
Group: System Environment/Libraries

# The tarball was created from Subversion using the following commands:
# svn co svn://t2.unl.edu/brian/lcmaps-plugin-static-mapping
# cd lcmaps-plugin-static-mapping
# ./bootstrap
# ./configure
# make dist
Source0: %{name}-%{version}.tar.gz

BuildRequires: lcmaps-interface

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot

%description
This plugin maps users who invoke glexec based upon a static mapfile.

%prep
%setup -q

%build

%configure
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT

make DESTDIR=$RPM_BUILD_ROOT install
rm $RPM_BUILD_ROOT%{_libdir}/lcmaps/liblcmaps_static_mapping.la
rm $RPM_BUILD_ROOT%{_libdir}/lcmaps/liblcmaps_static_mapping.a
mv $RPM_BUILD_ROOT%{_libdir}/lcmaps/liblcmaps_static_mapping.so \
   $RPM_BUILD_ROOT%{_libdir}/lcmaps/lcmaps_static_mapping.mod

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_libdir}/lcmaps/lcmaps_static_mapping.mod
%config(noreplace) %{_sysconfdir}/grid-security/glexec-mapfile

%changelog
* Sun Jan 15 2012 Brian Bockelman <bbockelm@cse.unl.edu> - 0.0.1-1
- Initial version.

