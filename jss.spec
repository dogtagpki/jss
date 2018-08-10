################################################################################
Name:           jss
################################################################################

Summary:        Java Security Services (JSS)
URL:            http://www.dogtagpki.org/wiki/JSS
License:        MPLv1.1 or GPLv2+ or LGPLv2+

Version:        4.5.0
Release:        1%{?_timestamp}%{?_commit_id}%{?dist}
# global         _phase -a1

# To generate the source tarball:
# $ git clone https://github.com/dogtagpki/jss.git
# $ cd jss
# $ git archive \
#     --format=tar.gz \
#     --prefix jss-VERSION/ \
#     -o jss-VERSION.tar.gz \
#     <version tag>
Source:         https://github.com/dogtagpki/%{name}/archive/v%{version}%{?_phase}/%{name}-%{version}%{?_phase}.tar.gz

# To create a patch for all changes since a version tag:
# $ git format-patch \
#     --stdout \
#     <version tag> \
#     > jss-VERSION-RELEASE.patch
# Patch: jss-VERSION-RELEASE.patch

################################################################################
# Build Dependencies
################################################################################

# autosetup
BuildRequires:  git

BuildRequires:  gcc-c++
BuildRequires:  nspr-devel >= 4.13.1
BuildRequires:  nss-devel >= 3.28.4-6
BuildRequires:  nss-tools >= 3.28.4-6
BuildRequires:  java-devel
BuildRequires:  jpackage-utils
BuildRequires:  slf4j
%if 0%{?rhel} && 0%{?rhel} <= 7
# no slf4j-jdk14
%else
BuildRequires:  slf4j-jdk14
%endif
BuildRequires:  apache-commons-lang
BuildRequires:  apache-commons-codec

%if 0%{?fedora} >= 25 || 0%{?rhel} > 7
BuildRequires:  perl-interpreter
%endif

Requires:       nss >= 3.28.4-6
Requires:       java-headless
Requires:       jpackage-utils
Requires:       slf4j
%if 0%{?rhel} && 0%{?rhel} <= 7
# no slf4j-jdk14
%else
Requires:       slf4j-jdk14
%endif
Requires:       apache-commons-lang
Requires:       apache-commons-codec

Conflicts:      ldapjdk < 4.20
Conflicts:      idm-console-framework < 1.2
Conflicts:      tomcatjss < 7.3.4
Conflicts:      pki-base < 10.6.5

%description
Java Security Services (JSS) is a java native interface which provides a bridge
for java-based applications to use native Network Security Services (NSS).
This only works with gcj. Other JREs require that JCE providers be signed.

################################################################################
%package javadoc
################################################################################

Summary:        Java Security Services (JSS) Javadocs
Group:          Documentation
Requires:       jss = %{version}-%{release}

%description javadoc
This package contains the API documentation for JSS.

################################################################################
%prep

%autosetup -n %{name}-%{version}%{?_phase} -p 1 -S git

################################################################################
%build

%set_build_flags

[ -z "$JAVA_HOME" ] && export JAVA_HOME=%{_jvmdir}/java
[ -z "$USE_INSTALLED_NSPR" ] && export USE_INSTALLED_NSPR=1
[ -z "$USE_INSTALLED_NSS" ] && export USE_INSTALLED_NSS=1

# Enable compiler optimizations
export BUILD_OPT=1

# Generate symbolic info for debuggers
XCFLAGS="-g $RPM_OPT_FLAGS"
export XCFLAGS

PKG_CONFIG_ALLOW_SYSTEM_LIBS=1
PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1

export PKG_CONFIG_ALLOW_SYSTEM_LIBS
export PKG_CONFIG_ALLOW_SYSTEM_CFLAGS

NSPR_INCLUDE_DIR=`/usr/bin/pkg-config --cflags-only-I nspr | sed 's/-I//'`
NSPR_LIB_DIR=`/usr/bin/pkg-config --libs-only-L nspr | sed 's/-L//'`

NSS_INCLUDE_DIR=`/usr/bin/pkg-config --cflags-only-I nss | sed 's/-I//'`
NSS_LIB_DIR=`/usr/bin/pkg-config --libs-only-L nss | sed 's/-L//'`

export NSPR_INCLUDE_DIR
export NSPR_LIB_DIR
export NSS_INCLUDE_DIR
export NSS_LIB_DIR

%if 0%{?__isa_bits} == 64
USE_64=1
export USE_64
%endif

# The Makefile is not thread-safe
make -C coreconf
make
make javadoc
make test_jss

################################################################################
%install

# There is no install target so we'll do it by hand

# jars
install -d -m 0755 $RPM_BUILD_ROOT%{_jnidir}
install -m 644 ../dist/xpclass.jar ${RPM_BUILD_ROOT}%{_jnidir}/jss4.jar

# We have to use the name libjss4.so because this is dynamically
# loaded by the jar file.
install -d -m 0755 $RPM_BUILD_ROOT%{_libdir}/jss
install -m 0755 ../dist/Linux*.OBJ/lib/libjss4.so ${RPM_BUILD_ROOT}%{_libdir}/jss/
pushd  ${RPM_BUILD_ROOT}%{_libdir}/jss
    ln -fs %{_jnidir}/jss4.jar jss4.jar
popd

# javadoc
install -d -m 0755 $RPM_BUILD_ROOT%{_javadocdir}/%{name}-%{version}
cp -rp ../dist/jssdoc/* $RPM_BUILD_ROOT%{_javadocdir}/%{name}-%{version}
cp -p jss.html $RPM_BUILD_ROOT%{_javadocdir}/%{name}-%{version}
cp -p *.txt $RPM_BUILD_ROOT%{_javadocdir}/%{name}-%{version}

# No ldconfig is required since this library is loaded by Java itself.
################################################################################
%files

%defattr(-,root,root,-)
%doc jss.html MPL-1.1.txt gpl.txt lgpl.txt
%{_libdir}/*
%{_jnidir}/*

################################################################################
%files javadoc

%defattr(-,root,root,-)
%{_javadocdir}/%{name}-%{version}/

################################################################################
%changelog
* Tue May 29 2018 Dogtag PKI Team <pki-devel@redhat.com> 4.5.0-0
- To list changes in <branch> since <tag>:
  $ git log --pretty=oneline --abbrev-commit --no-decorate <tag>..<branch>
