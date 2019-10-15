################################################################################
Name:           jss
################################################################################

Summary:        Java Security Services (JSS)
URL:            http://www.dogtagpki.org/wiki/JSS
License:        MPLv1.1 or GPLv2+ or LGPLv2+

Version:        4.6.2
Release:        1%{?_timestamp}%{?_commit_id}%{?dist}
# global         _phase -a1

# To generate the source tarball:
# $ git clone https://github.com/dogtagpki/jss.git
# $ cd jss
# $ git tag v4.5.<z>
# $ git push origin v4.5.<z>
# Then go to https://github.com/dogtagpki/jss/releases and download the source
# tarball.
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
BuildRequires:  make
BuildRequires:  cmake

BuildRequires:  gcc-c++
BuildRequires:  nspr-devel >= 4.13.1
BuildRequires:  nss-devel >= 3.30
BuildRequires:  nss-tools >= 3.30
BuildRequires:  java-devel
BuildRequires:  jpackage-utils
BuildRequires:  slf4j
BuildRequires:  glassfish-jaxb-api
%if 0%{?rhel} && 0%{?rhel} <= 7
# no slf4j-jdk14
%else
BuildRequires:  slf4j-jdk14
%endif
BuildRequires:  apache-commons-lang
BuildRequires:  apache-commons-codec

BuildRequires:  junit

Requires:       nss >= 3.30
Requires:       java-headless
Requires:       jpackage-utils
Requires:       slf4j
Requires:       glassfish-jaxb-api
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

# Enable compiler optimizations
export BUILD_OPT=1

# Generate symbolic info for debuggers
CFLAGS="-g $RPM_OPT_FLAGS"
export CFLAGS

# Check if we're in FIPS mode
modutil -dbdir /etc/pki/nssdb -chkfips true | grep -q enabled && export FIPS_ENABLED=1

# The Makefile is not thread-safe
rm -rf build && mkdir -p build && cd build
%cmake \
    -DJAVA_HOME=%{java_home} \
    -DJAVA_LIB_INSTALL_DIR=%{_jnidir} \
    ..

%{__make} all
%{__make} javadoc
ctest --output-on-failure

################################################################################
%install

# There is no install target so we'll do it by hand

# jars
install -d -m 0755 $RPM_BUILD_ROOT%{_jnidir}
install -m 644 build/jss4.jar ${RPM_BUILD_ROOT}%{_jnidir}/jss4.jar

# We have to use the name libjss4.so because this is dynamically
# loaded by the jar file.
install -d -m 0755 $RPM_BUILD_ROOT%{_libdir}/jss
install -m 0755 build/libjss4.so ${RPM_BUILD_ROOT}%{_libdir}/jss/
pushd  ${RPM_BUILD_ROOT}%{_libdir}/jss
    ln -fs %{_jnidir}/jss4.jar jss4.jar
popd

# javadoc
install -d -m 0755 $RPM_BUILD_ROOT%{_javadocdir}/%{name}-%{version}
cp -rp build/docs/* $RPM_BUILD_ROOT%{_javadocdir}/%{name}-%{version}
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
