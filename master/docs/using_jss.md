# Using JSS

Please make sure `libjss4.so` is included in your library path or set it via
the `LD_LIBRARY_PATH` environment variable. See `man 8 ld.so` for more
information. Alternatively, this can be done by setting `-Djava.library.path`
to the directory with `libjss4.so` on the command line of all Java programs
using JSS. Note that without `libjss4.so`, using JSS in nearly any capacity
will fail.

## Classpath Dependencies

To use JSS in your project after installation, you'll need to ensure the
following dependencies are available in your `CLASSPATH`:

 - `jss4.jar` -- provided by the `jss` package and installed to
   `/usr/lib/java/jss4.jar`.
 - `slf4j-api.jar` -- provided by the `slf4j` package and installed to
   `/usr/share/java/slf4j/slf4j-api.jar`.
 - `apache-commons-lang.jar` -- provided by the `apache-commons-lang` package
   and installed to `/usr/share/java/apache-commons-lang.jar`.
 - `jaxb-api.jar` -- provided by the `glassfish-jaxb-api` package
   and installed to `/usr/share/java/jaxb-api.jar`.

Note that the above paths and packages are for Fedora; for a list of packages
in Debian, please see the [dependencies document](dependencies.md). Note that
paths might differ between various platforms and versions of Fedora.

## Developing against JSS

We recommend referring to the javadoc distribution generated when JSS was
installed. On Fedora-like systems, this is provided by the `jss-javadoc`
package; for an online version tracking master, please refer to our
[live instance](https://dogtagpki.github.io/jss/javadoc/index.html).

## More Information

For more information about using JSS, please see our documentation on loading
the [`JSSProvider`](usage/jssprovider.md).
