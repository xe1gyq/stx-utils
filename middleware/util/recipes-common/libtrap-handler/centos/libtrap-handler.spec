Summary: CGTS Trap Handler for C/C++
Name: libtrap-handler
Version: 1.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: base
Packager: Wind River <info@windriver.com>
URL: unknown
Source: %name-%version.tar.gz

BuildRequires: gcc
BuildRequires: glibc

%description
CGTS Trap Handler is a library the provides signal handlers for fault
signals such as SIGSEGV and SIGILL. A crash report is generated and sent to
syslog. Add the following to your progrms early init code... .    #include
<trap_handler.h> .    init_trap_handler(); ... Compile and link with ....
-g -ltrap_handler -ldl ... Requires that binutils package be installed.

%package devel
Summary: CGTS Trap Handler for C/C++ - Development files
Group: devel
Requires: %{name} = %{version}-%{release}

%description devel
CGTS Trap Handler is a library the provides signal handlers for fault
signals such as SIGSEGV and SIGILL. A crash report is generated and sent to
syslog. Add the following to your progrms early init code... .    #include
<trap_handler.h> .    init_trap_handler(); ... Compile and link with ....
-g -ltrap_handler -ldl ... Requires that binutils package be installed.
This package contains symbolic links, header files, and related items
necessary for software development.

%prep
%autosetup

%build
make VER=%{version}

%install
rm -rf $RPM_BUILD_ROOT 
make DEST_DIR=$RPM_BUILD_ROOT LIB_DIR=%_libdir INC_DIR=%_includedir install_non_bb

%files devel
%defattr(-,root,root,-)
/usr/lib64/*.so
%dir "/usr/include/cgcs"
"/usr/include/cgcs/*.h"

%files
%license LICENSE
%defattr(-,root,root,-)
/usr/lib64/libtrap_handler.so.*

