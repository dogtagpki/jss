package Common;

use strict;
use warnings;

use Exporter qw(import);

# The below methods are used by build_java.pl and tests/all.pl; if the
# location of Common.pm ever changes, update the includes in those files
# to point to the new location.
our @EXPORT_OK = qw(get_jar_files);

sub get_jar_files {
    # Return a list of JAR files of the dependencies of JSS; in particular,
    # handle Debian vs OpenSUSE vs Fedora builds and the locations of relevant
    # jars on those platforms.
    our $jarFiles = "";

    if( $ENV{DEBIAN_BUILD} ) {
        $jarFiles = "/usr/share/java/slf4j-api.jar:/usr/share/java/commons-codec.jar:/usr/share/java/jaxb-api.jar";
        $jarFiles = "$jarFiles:/usr/share/java/commons-lang.jar"
    } elsif( $ENV{OPENSUSE_BUILD} ) {
        $jarFiles = "/usr/share/java/slf4j/api.jar:/usr/share/java/apache-commons-codec.jar:/usr/share/java/apache-commons-lang.jar";
        $jarFiles = "$jarFiles:/usr/share/java/jaxb-api.jar:/usr/share/java/apache-commons-lang.jar"
        # If some distro doesn't match the cases that we have identified
        # then add another elfsif section to handle it.
    } else {
        $jarFiles = "/usr/share/java/slf4j/api.jar:/usr/share/java/commons-codec.jar:/usr/share/java/jaxb-api.jar";
        $jarFiles = "$jarFiles:/usr/share/java/commons-lang.jar";
    }

    return $jarFiles;
}
