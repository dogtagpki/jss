# PKCS11Constants

As of release 4.5.1, JSS now ships with a set of constants that enable JSS to
work on JDK versions greater than 8. In particular, JDK 9+ introduced the
concepts of Modules to Java, allowing previously exported classes to be
restricted. This resulted in the complete removal of all `sun.*` classes;
previously, these internal implementation details were exposed by the JDK.

These changes are documented more at the following locations:

 - https://www.oracle.com/technetwork/java/faq-sun-packages-142232.html
 - https://www.oracle.com/corporate/features/understanding-java-9-modules.html
 - https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=875589
 - https://wiki.debian.org/Java/Java9Pitfalls

As a replacement, we built a utility to convert NSS's header files (`pkcs11t.h`
and `pkcs11n.h`) to Java. The following sections describe this system.


## Regenerating PKCS11Constants.java

There are a few cases where updating PKCS11Constants.java is necessary:

 - If NSS updates either of the two header files.
 - If certain constants need to be excluded.
 - If new constants need to be included.

In the former case, the CI job or container build of `pkcs11checks` will
fail, notifying us that this will need to be updated.

To do so, first make sure the system's NSS is up to date:

    dnf update --refresh
    dnf install nss-dev

Then, validate the location of the NSS header files; on Fedora, this location
is `/usr/include/nss3`:

    ls /usr/include/nss3/pkcs11{t,n}.h

Lastly, run the utility:

    python3 ./tools/build_pkcs11_constants.py --system \
        --pkcs11t /usr/include/nss3/pkcs11t.h \
        --pkcs11n /usr/include/nss3/pkcs11n.h \
        --output org/mozilla/jss/pkcs11/PKCS11Constants.java

While not required, it is suggested to use the `--system` flag to ensure
the values of `PKCS11Constants.java` are the same as the installed NSS
values.

After this, rebuild JSS and run the test suite on a JDK8 machine:

    source ./tools/autoenv.sh
    cd build && cmake .. && make clean all check

This will trigger the interoperability tests against the Sun values.


## `tools/build_pkcs11_constants.py`

This utility generates the `PKCS11Constants.java` from the contents of the
NSS header files. It has the following flags:

    -h / --help :: display the help text associated with the script

    --pkcs11t <path> :: path to the pkcs11t.h header file from a NSS
                        distribution; this header file contains the
                        general PKCS11 constants

    --pkcs11n <path> :: path to the pkcs11n.h header file from a NSS
                        distribution; this header file contains NSS
                        and Netscape-specific PKCS11 Constants

    -o <path> / --output <path> :: path to output the generated Java file to

    -s / --system :: assume the provided headers are from the system-installed
                     NSS; perform extended sanity checks by compiling the
                     parsed values and checking them against the NSS values

    -v / --verbose :: generate extended debug information in the form of
                      comments in the generated file; this includes information
                      about parsing, resolution, and if applicable, the output
                      of the system checks

The code of this program is heavily documented and is roughly organized
from more specific methods to more general methods (e.g., `main`). A few
things are of particular note:

 - This program attempts to verify correctness by ensuring that the internal
   representation of a constant is as a Python `int`; this ensures that we
   correctly parsed the value token and that, when we write the output,
   the value doesn't depend on any other constants.
 - This program treats all `#define`-d constants as if they were of a numeric
   type, with all values being written as hex encoded longs.
 - This program preserves the original ordering of constants, with constants in
   `pkcs11t.h` appearing before constants in `pkcs11n.h`.
 - This program currently parses only parenthesis in a token's value, but not
   curly braces or square braces; the latter two shouldn't be present in most
   numeric types. Any failure to parse as a numeric type is a parse error which
   fails the script.

For more information about this script, please refer to the comments therein.


## Java Test

Included in the test suite when run on a JDK8 machine is a test called
[`TestPKCS11Constants`](../org/mozilla/jss/tests/TestPKCS11Constants.java).
This uses reflection to compare the values of the PKCS11Constants.java
provided by JSS and the version provided by Sun, reporting constants in
four categories:

 1. Those which are "OK", i.e., present in both Sun and JSS with the same
    value.
 2. Those which are "JSS only", i.e., the constant name does not exist in
    the Sun distribution. These are not treated as errors.
 3. Those which are "Sun only", i.e., the constant name does not exist in
    the JSS distribution. These are not treated as errors.
 4. Those which are "not OK", i.e., present in both Sun and JSS but with
    different values associated to them. This is not an error.

Information about all constants is written to stdout during testing; please
manually review the "JSS only" and "Sun only" cases to see if any results
are unexpected.
