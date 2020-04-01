# Dependencies

## Build-time Dependencies

This project has the following dependencies:

 - [NSPR](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSPR)
 - [NSS](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS)
    - A c and c++ compiler such as [gcc](ttps://gcc.gnu.org/)
    - [zlib](https://zlib.net/)
 - [OpenJDK 1.8.0 or newer](http://openjdk.java.net/)
 - [CMake](https://cmake.org/)
 - [Apache Commons Lang](https://commons.apache.org/proper/commons-lang/)
 - [JavaEE JAXB](https://github.com/eclipse-ee4j/jaxb-ri)
 - [SLF4J](https://www.slf4j.org/)

Additionally, a zipping and unzipping program is required to create
reproducible builds.

To install these dependencies on Fedora, execute the following:

    sudo dnf install apache-commons-lang gcc-c++ java-devel jpackage-utils \
                     slf4j zlib-devel glassfish-jaxb-api nss-tools nss-devel \
                     cmake junit

To install these dependencies on Debian, execute the following:

    sudo apt-get install build-essential libcommons-lang-java libnss3-dev \
                         libslf4j-java default-jdk pkg-config zlib1g-dev \
                         libjaxb-api-java libnss3-tools cmake zip unzip \
                         junit4

## Test Suite Dependencies:

In addition to the dependencies above, the test suite requires the following
additional packages:

 - [SLF4J's JDK14 package](https://www.slf4j.org/api/org/slf4j/impl/JDK14LoggerAdapter.html)
 - [NSS's pk12util](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Reference/NSS_tools_:_pk12util)
 - [JUnit 4](https://junit.org/junit4/)

To install these dependencies on Fedora, execute the following:

    sudo dnf install nss nss-tools slf4j-jdk14 junit

To install these dependencies on Debian, execute the following:

    sudo apt-get install libnss3 libnss3-tools libslf4j-java \
                         junit4

## Run-time Dependencies

At run time, the following JARs are required to be specified on the
`CLASSPATH` of anyone wishing to use JSS:

 - `jss4.jar`
 - `slf4j-api.jar`
 - `apache-commons-lang.jar`
 - `jaxb-api.jar`

Note that these should already be installed when building JSS. For more
information, please refer to our documentation on using JSS:
[`docs/using_jss.md`](using_jss.md).

## Incompatibilities

Known NSS incompatibilities are documented in [`docs/nss.md`](nss.md).
