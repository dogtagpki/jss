package Common;

use strict;
use warnings;
use warnings FATAL => 'all';

use Exporter qw(import);

# The below methods are used by build_java.pl and tests/all.pl; if the
# location of Common.pm ever changes, update the includes in those files
# to point to the new location.
our @EXPORT_OK = qw(get_jar_files detect_jar_file);

sub detect_jar_file {
    # Detect the correct path to a jar file.
    # Die if the jar is missing.

    my @locations = qw(/usr/share/java /usr/lib/java);
    for my $location (@locations) {
        for my $candidate (@_) {
            my $path="$location/$candidate";
            if (-e $path) {
                return $path;
            }
        }
    }

    die "Can't find any jars for $_[1]";
}

sub get_jar_files {
    # Return a list of JAR files of the dependencies of JSS; in particular,
    # handle Debian vs OpenSUSE vs Fedora builds and the locations of relevant
    # jars on those platforms.

    our @jarFiles = ();
    my $slf4j = detect_jar_file("slf4j-api.jar", "slf4j/api.jar");
    my $codec = detect_jar_file("apache-commons-codec.jar", "commons-codec.jar");
    my $lang = detect_jar_file("apache-commons-lang.jar", "commons-lang.jar");
    my $jaxb = detect_jar_file("jaxb-api.jar");
    push(@jarFiles, $slf4j);
    push(@jarFiles, $codec);
    push(@jarFiles, $lang);
    push(@jarFiles, $jaxb);

    return join(':', @jarFiles);
}
