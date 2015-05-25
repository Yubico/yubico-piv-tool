Name:           yubico-piv-tool
Version:        0.1.6
Release:        1%{?dist}
Summary:        Yubikey Privilege and and Identification Card (PIV) tool

License:        GPL
URL:            https://developers.yubico.com/yubico-piv-tool/
Source0:        https://developers.yubico.com/yubico-piv-tool/Releases/%{name}-%{version}.tar.gz

%description
The Yubico PIV tool is used for interacting with the Privilege and
Identification Card (PIV) applet on a YubiKey NEO.

%package devel

Summary:  Development headers and libraries for yubico-piv-tool
Group:    Development/System
Requires: %{name} = %{version}-%{release}

%description devel
development files for yubico-piv-tool.


%prep
%setup -q


%build
%configure --enable-static=no
make %{?_smp_mflags}


%install
make install DESTDIR=$RPM_BUILD_ROOT

%files
%doc NEWS README COPYING ChangeLog
%{_libdir}/libykpiv.*
%{_bindir}/%{name}
%{_mandir}/man1/%{name}.1*

%files devel
%{_includedir}/ykpiv/*.h
%{_libdir}/pkgconfig/ykpiv.pc


%changelog
* Sun May 24 2015 Richard Harman <richard@richardharman.com> - 0.1.6-1
- Initial packaging
