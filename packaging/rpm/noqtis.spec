# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Fedora, EPEL, openSUSE-style RPM.
Name:           noqtis
Version:        0.1.0
Release:        1%{?dist}
Summary:        Post-quantum signing, KEMs and sealed input records in C11
License:        Apache-2.0 WITH LLVM-exception
URL:            https://github.com/rootcoder007/noqtis
Source0:        %{url}/archive/refs/tags/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  cmake

%description
noqtis records the exact files a result came from, signs that record with
post-quantum signatures (ML-DSA, SLH-DSA) and timestamps it, so anyone can
check later that nothing changed. This package has the shared library.

%package        devel
Summary:        Header, pkg-config file and CMake package for %{name}
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description    devel
The header, the pkg-config file and the CMake package config for building
against %{name}.

%prep
%autosetup

%build
%cmake -DNQSHARED=ON -DNQWERROR=OFF
%cmake_build

%install
%cmake_install

%check
%ctest

%files
%license LICENSE NOTICE
%doc README.md
%{_libdir}/libnoqtis.so.0{,.*}
%{_bindir}/noqtis

%files devel
%{_includedir}/noqtis.h
%{_libdir}/libnoqtis.so
%{_libdir}/pkgconfig/noqtis.pc
%{_libdir}/cmake/noqtis/

%changelog
* Wed Oct 28 2026 rootcoder007 <278967282+rootcoder007@users.noreply.github.com> - 0.1.0-1
- First package
