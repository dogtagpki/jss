################################################################################
Name:           jss
################################################################################

%global         product_id dogtag-jss

# Upstream version number:
%global         major_version 4
%global         minor_version 10
%global         update_version 0

Summary:        Java Security Services (JSS)
URL:            https://github.com/dogtagpki/jss
License:        MPLv1.1 or GPLv2+ or LGPLv2+

# For development (i.e. unsupported) releases, use x.y.z-0.n.<phase>.
# For official (i.e. supported) releases, use x.y.z-r where r >=1.
%global         release_number 0.1
Version:        %{major_version}.%{minor_version}.%{update_version}
Release:        %{release_number}%{?_timestamp}%{?_commit_id}%{?dist}
%global         _phase -alpha1

# To generate the source tarball:
# $ git clone https://github.com/dogtagpki/jss.git
# $ cd jss
# $ git tag v4.5.<z>
# $ git push origin v4.5.<z>
# Then go to https://github.com/dogtagpki/jss/releases and download the source
# tarball.
Source:         https://github.com/dogtagpki/jss/archive/v%{version}%{?_phase}/jss-%{version}%{?_phase}.tar.gz

# To create a patch for all changes since a version tag:
# $ git format-patch \
#     --stdout \
#     <version tag> \
#     > jss-VERSION-RELEASE.patch
# Patch: jss-VERSION-RELEASE.patch

################################################################################
# Java
################################################################################

%if 0%{?fedora} && 0%{?fedora} <= 32 || 0%{?rhel} && 0%{?rhel} <= 8
%define java_devel java-1.8.0-openjdk-devel
%define java_headless java-1.8.0-openjdk-headless
%define java_home /usr/lib/jvm/jre-1.8.0-openjdk
%else
%define java_devel java-11-openjdk-devel
%define java_headless java-11-openjdk-headless
%define java_home /usr/lib/jvm/jre-11-openjdk
%endif

################################################################################
# Build Options
################################################################################

# By default the build will not execute unit tests unless --with tests
# option is specified.

%bcond_with tests

################################################################################
# Build Dependencies
################################################################################

BuildRequires:  make
BuildRequires:  cmake >= 3.14
BuildRequires:  zip
BuildRequires:  unzip

BuildRequires:  gcc-c++
BuildRequires:  nss-devel >= 3.44
BuildRequires:  nss-tools >= 3.44
BuildRequires:  %{java_devel}
BuildRequires:  jpackage-utils
BuildRequires:  slf4j
BuildRequires:  glassfish-jaxb-api
BuildRequires:  slf4j-jdk14
BuildRequires:  apache-commons-lang3

BuildRequires:  junit

%description
Java Security Services (JSS) is a java native interface which provides a bridge
for java-based applications to use native Network Security Services (NSS).
This only works with gcj. Other JREs require that JCE providers be signed.

################################################################################
%package -n %{product_id}
################################################################################

Summary:        Java Security Services (JSS)

Requires:       nss >= 3.44
Requires:       %{java_headless}
Requires:       jpackage-utils
Requires:       slf4j
Requires:       glassfish-jaxb-api
Requires:       slf4j-jdk14
Requires:       apache-commons-lang3

Obsoletes:      jss < %{version}-%{release}
Provides:       jss = %{version}-%{release}
Provides:       jss = %{major_version}.%{minor_version}
Provides:       %{product_id} = %{major_version}.%{minor_version}

Conflicts:      ldapjdk < 4.20
Conflicts:      idm-console-framework < 1.2
Conflicts:      tomcatjss < 7.6.0
Conflicts:      pki-base < 10.10.0

%description -n %{product_id}
Java Security Services (JSS) is a java native interface which provides a bridge
for java-based applications to use native Network Security Services (NSS).
This only works with gcj. Other JREs require that JCE providers be signed.

################################################################################
%package -n %{product_id}-javadoc
################################################################################

Summary:        Java Security Services (JSS) Javadocs

Obsoletes:      jss-javadoc < %{version}-%{release}
Provides:       jss-javadoc = %{version}-%{release}
Provides:       jss-javadoc = %{major_version}.%{minor_version}
Provides:       %{product_id}-javadoc = %{major_version}.%{minor_version}

%description -n %{product_id}-javadoc
This package contains the API documentation for JSS.

################################################################################
%prep
################################################################################

%autosetup -n jss-%{version}%{?_phase} -p 1

################################################################################
%build
################################################################################

%set_build_flags

# Enable compiler optimizations
export BUILD_OPT=1

# Generate symbolic info for debuggers
CFLAGS="-g $RPM_OPT_FLAGS"
export CFLAGS

# Check if we're in FIPS mode
modutil -dbdir /etc/pki/nssdb -chkfips true | grep -q enabled && export FIPS_ENABLED=1

# The Makefile is not thread-safe
%cmake \
    -DVERSION=%{version} \
    -DJAVA_HOME=%{java_home} \
    -DJAVA_LIB_INSTALL_DIR=%{_jnidir} \
    -DJSS_LIB_INSTALL_DIR=%{_libdir}/jss \
    -B %{_vpath_builddir}

cd %{_vpath_builddir}

%{__make} \
    VERBOSE=%{?_verbose} \
    CMAKE_NO_VERBOSE=1 \
    --no-print-directory \
    all

%{__make} \
    VERBOSE=%{?_verbose} \
    CMAKE_NO_VERBOSE=1 \
    --no-print-directory \
    javadoc

%if %{with tests}
ctest --output-on-failure
%endif

################################################################################
%install
################################################################################

cd %{_vpath_builddir}

%{__make} \
    VERBOSE=%{?_verbose} \
    CMAKE_NO_VERBOSE=1 \
    DESTDIR=%{buildroot} \
    INSTALL="install -p" \
    --no-print-directory \
    install

################################################################################
%files -n %{product_id}
################################################################################

%defattr(-,root,root,-)
%doc jss.html
%license MPL-1.1.txt gpl.txt lgpl.txt
%{_libdir}/*
%{_jnidir}/*

################################################################################
%files -n %{product_id}-javadoc
################################################################################

%defattr(-,root,root,-)
%{_javadocdir}/jss-%{version}/

################################################################################
%changelog
* Tue May 29 2018 Dogtag PKI Team <devel@lists.dogtagpki.org> 4.5.0-0
- To list changes in <branch> since <tag>:
  $ git log --pretty=oneline --abbrev-commit --no-decorate <tag>..<branch>
