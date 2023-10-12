################################################################################
Name:           jss
################################################################################

%global         product_id dogtag-jss

# Upstream version number:
%global         major_version 5
%global         minor_version 5
%global         update_version 0

# Downstream release number:
# - development/stabilization (unsupported): 0.<n> where n >= 1
# - GA/update (supported): <n> where n >= 1
%global         release_number 0.1

# Development phase:
# - development (unsupported): alpha<n> where n >= 1
# - stabilization (unsupported): beta<n> where n >= 1
# - GA/update (supported): <none>
%global         phase alpha2

%undefine       timestamp
%undefine       commit_id

Summary:        Java Security Services (JSS)
URL:            https://github.com/dogtagpki/jss
License:        (MPL-1.1 or GPL-2.0-or-later or LGPL-2.1-or-later) and Apache-2.0
Version:        %{major_version}.%{minor_version}.%{update_version}
Release:        %{release_number}%{?phase:.}%{?phase}%{?timestamp:.}%{?timestamp}%{?commit_id:.}%{?commit_id}%{?dist}

# To generate the source tarball:
# $ git clone https://github.com/dogtagpki/jss.git
# $ cd jss
# $ git tag v4.5.<z>
# $ git push origin v4.5.<z>
# Then go to https://github.com/dogtagpki/jss/releases and download the source
# tarball.
Source:         https://github.com/dogtagpki/jss/archive/v%{version}%{?phase:-}%{?phase}/jss-%{version}%{?phase:-}%{?phase}.tar.gz

# To create a patch for all changes since a version tag:
# $ git format-patch \
#     --stdout \
#     <version tag> \
#     > jss-VERSION-RELEASE.patch
# Patch: jss-VERSION-RELEASE.patch

%if 0%{?java_arches:1}
ExclusiveArch: %{java_arches}
%else
ExcludeArch: i686
%endif

################################################################################
# Java
################################################################################

%define java_devel java-17-openjdk-devel
%define java_headless java-17-openjdk-headless
%define java_home %{_jvmdir}/jre-17-openjdk

################################################################################
# Build Options
################################################################################

# By default the javadoc package will be built unless --without javadoc
# option is specified.

%bcond_without javadoc

# By default the tests package will be built and the tests will executed
# unless --without tests option is specified.

%bcond_without tests

################################################################################
# Build Dependencies
################################################################################

BuildRequires:  make
BuildRequires:  cmake >= 3.14
BuildRequires:  zip
BuildRequires:  unzip

BuildRequires:  gcc-c++
BuildRequires:  nss-devel >= 3.66
BuildRequires:  nss-tools >= 3.66

BuildRequires:  %{java_devel}
BuildRequires:  maven-local
BuildRequires:  mvn(org.apache.commons:commons-lang3)
BuildRequires:  mvn(org.slf4j:slf4j-api)
BuildRequires:  mvn(org.slf4j:slf4j-jdk14)

%description
Java Security Services (JSS) is a java native interface which provides a bridge
for java-based applications to use native Network Security Services (NSS).
This only works with gcj. Other JREs require that JCE providers be signed.

################################################################################
%package -n %{product_id}
################################################################################

Summary:        Java Security Services (JSS)

Requires:       nss >= 3.66

Requires:       %{java_headless}
Requires:       mvn(org.apache.commons:commons-lang3)
Requires:       mvn(org.slf4j:slf4j-api)
Requires:       mvn(org.slf4j:slf4j-jdk14)

Obsoletes:      jss < %{version}-%{release}
Provides:       jss = %{version}-%{release}
Provides:       jss = %{major_version}.%{minor_version}
Provides:       %{product_id} = %{major_version}.%{minor_version}

Conflicts:      ldapjdk < 4.20
Conflicts:      idm-console-framework < 1.2
Conflicts:      pki-base < 10.10.0

%description -n %{product_id}
Java Security Services (JSS) is a java native interface which provides a bridge
for java-based applications to use native Network Security Services (NSS).
This only works with gcj. Other JREs require that JCE providers be signed.

################################################################################
%package -n %{product_id}-tomcat
################################################################################

Summary:        Java Security Services (JSS) Connector for Tomcat

# Tomcat
BuildRequires:  mvn(org.apache.tomcat:tomcat-catalina) >= 9.0.62
BuildRequires:  mvn(org.apache.tomcat:tomcat-coyote) >= 9.0.62
BuildRequires:  mvn(org.apache.tomcat:tomcat-juli) >= 9.0.62

Requires:       %{product_id} = %{version}-%{release}
Requires:       mvn(org.apache.tomcat:tomcat-catalina) >= 9.0.62
Requires:       mvn(org.apache.tomcat:tomcat-coyote) >= 9.0.62
Requires:       mvn(org.apache.tomcat:tomcat-juli) >= 9.0.62

# Tomcat JSS has been replaced with JSS Connector for Tomcat.
# This will remove installed Tomcat JSS packages.
Obsoletes:      tomcatjss <= 8.5
Conflicts:      tomcatjss <= 8.5

%if 0%{?rhel} <= 8
# PKI Servlet Engine has been replaced with Tomcat.
# This will remove installed PKI Servlet Engine packages.
Obsoletes:      pki-servlet-engine <= 9.0
Conflicts:      pki-servlet-engine <= 9.0
%endif

%description -n %{product_id}-tomcat
JSS Connector for Tomcat is a Java Secure Socket Extension (JSSE)
module for Apache Tomcat that uses Java Security Services (JSS),
a Java interface to Network Security Services (NSS).

%if %{with javadoc}
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
%endif

%if %{with tests}
################################################################################
%package -n %{product_id}-tests
################################################################################

Summary:        Java Security Services (JSS) Tests

BuildRequires:  mvn(org.junit.jupiter:junit-jupiter)
BuildRequires:  mvn(org.opentest4j:opentest4j)

%description -n %{product_id}-tests
This package provides test suite for JSS.

# with tests
%endif

################################################################################
%prep
################################################################################

%autosetup -n jss-%{version}%{?phase:-}%{?phase} -p 1

# disable native modules since they will be built by CMake
%pom_disable_module native
%pom_disable_module symkey

# do not ship examples
%pom_disable_module examples

# flatten-maven-plugin is not available in RPM
%pom_remove_plugin org.codehaus.mojo:flatten-maven-plugin

# assign Maven artifacts to RPM packages
%mvn_package org.dogtagpki.jss:jss-parent      jss-base
%mvn_package org.dogtagpki.jss:jss-tomcat-9.0  jss-tomcat

################################################################################
%build
################################################################################

# Set build flags for CMake
# (see /usr/lib/rpm/macros.d/macros.cmake)
%set_build_flags

export JAVA_HOME=%{java_home}

# Enable compiler optimizations
export BUILD_OPT=1

# Generate symbolic info for debuggers
CFLAGS="-g $RPM_OPT_FLAGS"
export CFLAGS

# Check if we're in FIPS mode
modutil -dbdir /etc/pki/nssdb -chkfips true | grep -q enabled && export FIPS_ENABLED=1

# build Java code, run Java tests, and build Javadoc with Maven
%mvn_build -s %{!?with_tests:-f} %{!?with_javadoc:-j}

# create links to Maven-built classes for CMake
mkdir -p %{_vpath_builddir}/classes/jss
ln -sf ../../../base/target/classes/org %{_vpath_builddir}/classes/jss
%if %{with tests}
mkdir -p %{_vpath_builddir}/classes/tests
ln -sf ../../../base/target/test-classes/org %{_vpath_builddir}/classes/tests
%endif

# create links to Maven-built JAR files for CMake
ln -sf ../base/target/jss.jar %{_vpath_builddir}
%if %{with tests}
ln -sf ../base/target/jss-tests.jar %{_vpath_builddir}
%endif

# create links to Maven-built headers for CMake
mkdir -p %{_vpath_builddir}/include/jss
ln -sf ../../../base/target/include/_jni %{_vpath_builddir}/include/jss/_jni

# mark Maven-built targets so that CMake will not rebuild them
mkdir -p %{_vpath_builddir}/.targets
touch %{_vpath_builddir}/.targets/finished_generate_java
%if %{with tests}
touch %{_vpath_builddir}/.targets/finished_tests_generate_java
%endif
%if %{with javadoc}
touch %{_vpath_builddir}/.targets/finished_generate_javadocs
%endif

# build native code and run native tests with CMake
./build.sh \
    %{?_verbose:-v} \
    --work-dir=%{_vpath_builddir} \
    --prefix-dir=%{_prefix} \
    --include-dir=%{_includedir} \
    --lib-dir=%{_libdir} \
    --sysconf-dir=%{_sysconfdir} \
    --share-dir=%{_datadir} \
    --cmake=%{__cmake} \
    --java-home=%{java_home} \
    --jni-dir=%{_jnidir} \
    --version=%{version} \
    --without-java \
    --without-javadoc \
    %{!?with_tests:--without-tests} \
    dist

################################################################################
%install
################################################################################

# install Java binaries and Javadoc
%mvn_install

# install jss.jar
mkdir -p %{buildroot}%{_javadir}/jss
cp base/target/jss.jar %{buildroot}%{_javadir}/jss/jss.jar

# create links for backward compatibility
mkdir -p %{buildroot}%{_jnidir}
ln -sf ../../..%{_javadir}/jss/jss.jar %{buildroot}%{_jnidir}/jss.jar

mkdir -p %{buildroot}%{_libdir}/jss
ln -sf ../../..%{_javadir}/jss/jss.jar %{buildroot}%{_libdir}/jss/jss.jar

# install native binaries
./build.sh \
    %{?_verbose:-v} \
    --work-dir=%{_vpath_builddir} \
    --install-dir=%{buildroot} \
    --without-java \
    install

# install tests binaries
%if %{with tests}
mkdir -p %{buildroot}%{_datadir}/jss/tests/lib
cp base/target/jss-tests.jar %{buildroot}%{_datadir}/jss/tests/lib
%endif

################################################################################
%files -n %{product_id} -f .mfiles-jss-base
################################################################################

%doc jss.html
%license MPL-1.1.txt gpl.txt lgpl.txt symkey/LICENSE
%{_javadir}/jss/jss.jar
%{_jnidir}/jss.jar
%{_libdir}/jss/jss.jar
%{_libdir}/jss/libjss.so
%{_libdir}/jss/libjss-symkey.so

################################################################################
%files -n %{product_id}-tomcat -f .mfiles-jss-tomcat
################################################################################

%if %{with javadoc}
################################################################################
%files -n %{product_id}-javadoc -f .mfiles-javadoc
################################################################################
%endif

%if %{with tests}
################################################################################
%files -n %{product_id}-tests
################################################################################

%{_datadir}/jss/tests/

# with tests
%endif

################################################################################
%changelog
* Tue May 29 2018 Dogtag PKI Team <devel@lists.dogtagpki.org> 4.5.0-0
- To list changes in <branch> since <tag>:
  $ git log --pretty=oneline --abbrev-commit --no-decorate <tag>..<branch>
