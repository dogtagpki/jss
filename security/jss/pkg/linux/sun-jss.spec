Summary: Network Security Services for Java
Name: NAME_REPLACE
Vendor: Sun Microsystems
Version: VERSION_REPLACE
Release: RELEASE_REPLACE
Copyright: MPL/GPL
Group: System Environment/Base
Source: %{name}-%{version}.tar.gz
ExclusiveOS: Linux
BuildRoot: %_topdir/%{name}-root

Requires: sun-nspr >= 4.1.2, sun-nss >= 3.3.4
        
%description
Network Security Services for Java (JSS) is a set of libraries designed
to support cross-platform development of security-enabled server
applications. Applications built with JSS can support SSL v2
and v3, TLS, PKCS #5, PKCS #7, PKCS #11, PKCS #12, S/MIME,
X.509 v3 certificates, and other security standards.  See:
http://www.mozilla.org/projects/security/pki/jss/

%package devel
Summary: Development Libraries for Network Security Services for Java
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}

%description devel
Header files for doing development with Network Security Services for Java.

%prep
%setup -c

%build

%install
rm -rf $RPM_BUILD_ROOT
mkdir $RPM_BUILD_ROOT
cd $RPM_BUILD_ROOT
tar xvzf $RPM_SOURCE_DIR/%{name}-%{version}.tar.gz

%clean
rm -rf $RPM_BUILD_ROOT
