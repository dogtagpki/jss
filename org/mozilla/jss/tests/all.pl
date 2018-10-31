#!/usr/bin/perl
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

use strict;
use warnings;
use warnings FATAL => 'all';

use Socket;
use File::Basename;
use Cwd qw(abs_path);
use POSIX 'uname';

# change the line below if we reorganize the code; must
# point to the location with Common.pm
use lib dirname(dirname abs_path $0) . '/../../../lib';

use Common qw(get_jar_files);

# dist <dist_dir> <NSS bin dir> <NSS lib dir> <JSS lib dir>
# release <java release dir> <nss release dir> <nspr release dir>
# auto   (test the current build directory)

sub usage {
    print "Usage:\n";
    print "$0 dist <dist_dir> <NSS bin_dir> <NSS lib dir> <JSS lib dir> <jss jar>\n";
    print "$0 release <jss release dir> <nss release dir> "
        . "<nspr release dir> <jss jar>\n";
    print "$0 auto\n";
    exit(1);
}

# Force Perl to do unbuffered output
# to avoid having Java and Perl output out of sync.
$| = 1;

# Global variables
my $java           = "";
my $java_version   = "";
my $testdir        = "";
my $testrun        = 0;
my $testpass       = 0;
my $nss_lib_dir    = "";
my $jss_lib_dir    = "";
my $pathsep        = ":";
my $scriptext      = "sh";
my $exe_suffix     = "";
my $lib_suffix     = ".so";
my $lib_jss        = "libjss";
my $jss_rel_dir    = "";
my $jss_classpath  = "";
my $serverPort     = 2876;
my $localhost      = "localhost";
my $hostname       = $localhost;
my $dbPwd          = "m1oZilla";
my $configfile     = "";
my $keystore       = "";
my $certSN_file    = "";
my $certSN         = 0;
my $osname         = "";
my $host           = "";
my $release        = "";
($osname,$host,$release)    = uname;

# checkPort will return a free Port number
# otherwise it will die after trying 10 times.
sub checkPort {
   my ($p) = @_;
   my $localhost = inet_aton("localhost");
   my $max = $p + 20; # try to find a port 10 times
   my $port = sockaddr_in($p, $localhost);

   #create a socket
   socket(SOCKET, PF_INET, SOCK_STREAM, getprotobyname('tcp'))
   || die "Unable to create socket: $!\n";

   #loop until you find a free port
   while (connect(SOCKET, $port) && $p < $max) {
         print "$p is in use trying to find another port.\n";
         $p = $p + 1;
         $port = sockaddr_in($p, $localhost);
   }
   close SOCKET || die "Unable to close socket: $!\n";
   if ($p == $max) {
      die "Unable to find a free port..\n";
   }

   return $p;
}


# used in all test invocations
my $run_shell    = "";
my $pwfile       = "";
my $nss_bin_dir  = "";
my $classpath    = "";
my $ld_lib_path  = "";
my $nspr_lib_dir = "";

sub setup_vars {
    my $argv = shift;

    my $truncate_lib_path = 1;
    $run_shell = "";
    if( $osname =~ /HP/ ) {
        $ld_lib_path = "SHLIB_PATH";
        $scriptext = "sh";
        $lib_suffix = ".sl";
    } elsif( $osname =~ /Darwin/) {
        $ld_lib_path = "DYLD_LIBRARY_PATH";
        $lib_suffix = ".jnilib";
    } elsif( $osname =~ /mingw/i ) {
    	print "We are mingw\n";
        $ld_lib_path = "PATH";
        $truncate_lib_path = 0;
        $pathsep = ":";
        $exe_suffix = ".exe";
        $lib_suffix = ".dll";
        $lib_jss    = "jss";
        $scriptext = "sh";
        $run_shell = "sh.exe";
    } elsif( $osname =~ /win/i ) {
        $ld_lib_path = "PATH";
        $truncate_lib_path = 0;
        $pathsep = ";";
        $exe_suffix = ".exe";
        $lib_suffix = ".dll";
        $lib_jss    = "jss";
        $run_shell = "sh.exe";
    } else {
        $ld_lib_path = "LD_LIBRARY_PATH";
        $scriptext = "sh";
    }

    $ENV{$ld_lib_path} = "" if $truncate_lib_path;

    if( $$argv[0] eq "dist" ) {
        shift @$argv;

        if (scalar @$argv != 5) {
            usage("incorrect dist parameters");
        }

        my $dist_dir = shift @$argv;
        $nss_bin_dir = shift @$argv;
        $nss_lib_dir = shift @$argv;
        $jss_lib_dir = shift @$argv;
        $jss_classpath = shift @$argv;

        $jss_rel_dir   = "$dist_dir/classes/org";

        ( -f $jss_classpath ) or die "$jss_classpath does not exist";

        $ENV{$ld_lib_path} = $ENV{$ld_lib_path} . $pathsep . "$nss_lib_dir";

    } elsif( $$argv[0] eq "auto" ) {
        my $dist_dir = `make dist_dir`;
        my $obj_dir = `make obj_dir`;
        chomp($dist_dir);
        chomp($obj_dir);
        chomp( $dist_dir = `(cd $dist_dir ; pwd)`);
        chomp( $obj_dir = `(cd $obj_dir ; pwd)`);

        $nss_bin_dir   = "$obj_dir/bin";
        $nss_lib_dir   = "$obj_dir/lib";
        $jss_lib_dir   = "$obj_dir/lib";
        $jss_rel_dir   = "$dist_dir/classes/org";
        $jss_classpath = "$dist_dir/xpclass.jar";

        ( -f $jss_classpath ) or die "$jss_classpath does not exist";

        #$ENV{$ld_lib_path} = $ENV{$ld_lib_path} . $pathsep . "$nss_lib_dir";
        $ENV{$ld_lib_path} = "$nss_lib_dir";

    } elsif( $$argv[0] eq "release" ) {
        shift @$argv;

        $jss_rel_dir     = shift @$argv or usage();
        my $nss_rel_dir  = shift @$argv or usage();
        my $nspr_rel_dir = shift @$argv or usage();
        $jss_classpath   = shift @$argv or usage();

        $nspr_lib_dir = "$nspr_rel_dir/lib";
        $nss_bin_dir = "$nss_rel_dir/bin";
        $nss_lib_dir = "$nss_rel_dir/lib";
        $jss_lib_dir = "$jss_rel_dir/lib";

        $ENV{$ld_lib_path} =
                "$jss_lib_dir" . $pathsep .
                "$nss_lib_dir" . $pathsep .
                "$nspr_lib_dir" . $pathsep .
                $ENV{$ld_lib_path};

    } else {
        usage();
    }

    if (defined $ENV{PORT_JSSE_SERVER} && $ENV{PORT_JSSE_SERVER}) {
       $serverPort = $ENV{PORT_JSSE_SERVER};
    }

    if (defined $ENV{PORT_JSS_SERVER} && $ENV{PORT_JSS_SERVER}) {
       $serverPort = $ENV{PORT_JSS_SERVER};
    }

    unless( $ENV{JAVA_HOME} ) {
        print "Must set JAVA_HOME environment variable\n";
        exit(1);
    }

    if ($osname =~ /Darwin/) {
        $java = "$ENV{JAVA_HOME}/bin/java";
    } else {
        $java = "$ENV{JAVA_HOME}/bin/java$exe_suffix";
    }

    #
    # Use 64-bit Java on AMD64.
    #

    my $java_64bit = 0;
    if ($osname eq "SunOS") {
        if ($ENV{USE_64}) {
            my $cpu = `/usr/bin/isainfo -n`;
            chomp $cpu;
            if ($cpu eq "amd64") {
                $java = "$ENV{JAVA_HOME}/jre/bin/amd64/java$exe_suffix";
                $java_64bit = 1;
            }
        }
    }

    if ( $osname =~ /_NT/i ) {
       $java_64bit = 1;
    }

    (-f $java) or die "'$java' does not exist\n";

    #MAC OS X have the -Djava.library.path for the JSS JNI library
    if ($osname =~ /Darwin/ || $osname =~ /Linux/) {
        $java = $java . " -Djava.library.path=$jss_lib_dir";
    }

    # Check the java version
    $java_version = `$java -version 2>&1`;

    my $jarFiles = Common::get_jar_files;
    $jarFiles = "$jarFiles:" . Common::detect_jar_file "slf4j-jdk14.jar", "slf4j/jdk14.jar";
    $classpath = "$jarFiles:$jss_classpath";

    $pwfile = "passwords";

    # testdir = /<ws>/mozilla/tests_results/jss/<hostname>.<version>
    # $all_dir = Directory where all.pl is
    my $all_dir = dirname($0);
    # Find where mozilla directory is
    my $base_mozilla = $all_dir . "/../../../../..";
    my $abs_base_mozilla = abs_path($base_mozilla);
    # $result_dir = Directory where the results are (mozilla/tests_results/jss)
    # First check the one above
    my $result_dir =  $abs_base_mozilla . "/tests_results";
    if (! -d $result_dir) {
       mkdir( $result_dir, 0755 ) or die;
    }
    # Now the one for jss
    $result_dir =  $abs_base_mozilla . "/tests_results/jss";
    if( ! -d $result_dir ) {
      mkdir( $result_dir, 0755 ) or die;
    }
    # $host = hostname
    # $version = test run number (first = 1). Stored in $result_dir/$host
    my $version = "";
    my $version_file = $result_dir ."/" . $host;
    if ( -f $version_file) {
      open (VERSION, "< $version_file") || die "couldn't open " . $version_file . " for read";
      $version = <VERSION>;
      close (VERSION);
      chomp $version;
      $version = $version + 1;
    } else {
      $version = 1;
    }
    # write the version in the file
    open (VERSION, "> $version_file")  || die "couldn't open " . $version_file . " for write";
    print VERSION $version . "\n";
    close (VERSION);
    # Finally, set $testdir
    $testdir = $result_dir . "/" . $host . "." . $version;

    #in case multiple tests are being run on the same machine increase
    #the port numbers with version number * 10

    $serverPort = $serverPort + ($version * 10);

    outputEnv();
}

sub updateCertSN() {

    # $certSN = certificate serial number (first = 100). Stored in $testdir/cert-SN
    $certSN_file = $testdir ."/" . "cert-SN";
    if ( -f $certSN_file) {
      open (CERT_SN, "< $certSN_file") || die "couldn't open " . $certSN_file . " for read";
      $certSN = <CERT_SN>;
      close (CERT_SN);
      chomp $certSN;
      $certSN = $certSN + 10;
    } else {
      $certSN = 100;
    }

    # write the version in the file
    open (CERT_SN, "> $certSN_file")  || die "couldn't open " . $certSN_file . " for write";
    print CERT_SN $certSN . "\n";
    close (CERT_SN);

}

sub outputEnv {

   print "*****ENVIRONMENT*****\n";
   print "java=$java\n";
   print "$ld_lib_path=$ENV{$ld_lib_path}\n";
   print "CLASSPATH=$classpath\n";
   if (defined $ENV{BUILD_OPT}) {
      print "BUILD_OPT=$ENV{BUILD_OPT}\n";
   }
   if (defined $ENV{USE_64}) {
      print "USE_64=$ENV{USE_64}\n";
   }
   print "testdir=$testdir\n";
   print "serverPort=$serverPort\n";
   print "LIB_SUFFIX=$lib_suffix\n";
   print "osname=$osname\n";
   print "release=$release\n";
   print "which perl=";
   system ("which perl");
   system ("perl -version | grep \"This is perl\"");
   system ("$java -version");
}

sub createpkcs11_cfg {

    $configfile = $testdir . "/" . "nsspkcs11.cfg";
    $keystore = $testdir . "/" . "keystore";
    if ( -f $configfile ) {
        print "configfile all ready exists";
       return;
    }

    my $nsslibdir = $nss_lib_dir;
    my $tdir = $testdir;

    #On windows make sure the path starts with c:
    if ($osname =~ /_NT/i) {
       substr($nsslibdir, 0, 2) = 'c:';
       substr($tdir, 0, 2) = 'c:';
    }
    #the test for java 1.5 or 1.6 relies on the JAVA_HOME path to have the version
    #this is the case for all the build machines and tinderboxes.
    if ( $java_version =~ /1.6/i) {
       # java 6
       # http://java.sun.com/javase/6/docs/technotes/guides/security/p11guide.html
       # note some OS can read the 1.5 configuration but not all can.
       open (CONFIG, "> $configfile")  || die "couldn't open " . $configfile . " for write";
       print CONFIG "name=NSS\n";
       print CONFIG "nssLibraryDirectory=" . "$nsslibdir\n";
       print CONFIG "nssSecmodDirectory=$tdir\n";
       print CONFIG "nssDbMode=readWrite\n";
       print CONFIG "nssModule=keystore\n";
       close (CONFIG);

    } else { # default

       # java 5
       #http://java.sun.com/j2se/1.5.0/docs/guide/security/p11guide.html
       open (CONFIG, "> $configfile")  || die "couldn't open " . $configfile . " for write";
       print CONFIG "name=NSS\n";
       if ($lib_suffix eq ".jnilib") {
           print CONFIG "library=" . $nsslibdir  . "/libsoftokn3.dylib\n";
       } else {
           print CONFIG "library=" . $nsslibdir  . "/libsoftokn3$lib_suffix\n";
       }
       print CONFIG "nssArgs=\"configdir=\'". $tdir . "\' ";
       print CONFIG "certPrefix=\'\' keyPrefix=\'\' secmod=\'secmod.db\'\"\n";
       print CONFIG "slot=2\n";
       close (CONFIG);

    }
    print "nsspkcs11=$configfile\n";
}

sub run_ssl_test {
    my $testname = shift;
    my $serverCommand = shift;
    my $clientCommand = shift;

    print "\n============= $testname \n";
    print "$serverCommand \n";
    my $result = system("$serverCommand");
    if ($result != 0) {
        print "launching server FAILED with return value $result\n";
        return;
    }
    sleep 5;
    print "\nSSL Server is invoked using port $serverPort \n" ;
    print "$clientCommand \n";
    $result = system("$clientCommand");
    $result >>=8;
    print_case_result ($result, $testname);

    $serverPort=$serverPort+1;
    $serverPort = checkPort($serverPort);
}

sub run_test {
    my $testname = shift;
    my $command = shift;

    print "\n============= $testname \n";
    print "$command \n";
    my $result = system("$command");
    $result >>=8;
    print_case_result ($result, $testname);
}

sub print_case_result {
    my $result = shift;
    my $testname = shift;

    $testrun++;
    if ($result == 0) {
        $testpass++;
        print "JSSTEST_CASE $testrun ($testname): PASS\n";
    } else {
        print "JSSTEST_CASE $testrun ($testname): FAILED return value $result\n";
    }
}

setup_vars(\@ARGV);

my $signingToken = "Internal Key Storage Token";


print "*********************\n";

#
# Make the test database directory
#
if( ! -d $testdir ) {
    mkdir( $testdir, 0755 ) or die;
}
{
    my @dbfiles =
        ("$testdir/cert8.db", "$testdir/key3.db", "$testdir/secmod.db", "$testdir/rsa.pfx");
    (grep{ -f } @dbfiles)  and die "There is already an old database in $testdir";
    my $result = system("cp $nss_lib_dir/*nssckbi* $testdir");
    $result >>= 8;
    # $result and die "Failed to copy built-ins library";
}

print "creating pkcs11config file\n";
createpkcs11_cfg;

my $serverCommand;

my $pk12util = "pk12util$exe_suffix";
if ($nss_bin_dir) {
    $pk12util = "$nss_bin_dir/$pk12util";
}

my $testname = "";
my $command  = "";

$testname = "Test UTF-8 Converter";
$command = "$java -ea -cp $classpath org.mozilla.jss.tests.UTF8ConverterTest";
run_test($testname, $command);

$testname = "Setup DBs";
$command = "$java -cp $classpath org.mozilla.jss.tests.SetupDBs $testdir $pwfile";
run_test($testname, $command);

updateCertSN();
$testname = "Generate known RSA cert pair";
$command = "$java -cp $classpath org.mozilla.jss.tests.GenerateTestCert $testdir $pwfile $certSN localhost SHA-256/RSA CA_RSA Server_RSA Client_RSA";
run_test($testname, $command);

updateCertSN();
$testname = "Generate known ECDSA cert pair";
$command = "$java -cp $classpath org.mozilla.jss.tests.GenerateTestCert $testdir $pwfile $certSN localhost SHA-256/EC CA_ECDSA Server_ECDSA Client_ECDSA";
run_test($testname, $command);

updateCertSN();
$testname = "Generate known DSS cert pair";
$command = "$java -cp $classpath org.mozilla.jss.tests.GenerateTestCert $testdir $pwfile $certSN localhost SHA-1/DSA CA_DSS Server_DSS Client_DSS";
run_test($testname, $command);

$testname = "Create PKCS11 cert to PKCS12 rsa.pfx";
$command = "$pk12util -o $testdir/rsa.pfx -n CA_RSA -d $testdir -K $dbPwd -W $dbPwd";
run_test($testname, $command);

$testname = "Create PKCS11 cert to PKCS12 ecdsa.pfx";
$command = "$pk12util -o $testdir/ecdsa.pfx -n CA_ECDSA -d $testdir -K $dbPwd -W $dbPwd";
run_test($testname, $command);

$testname = "Create PKCS11 cert to PKCS12 dss.pfx";
$command = "$pk12util -o $testdir/dss.pfx -n CA_DSS -d $testdir -K $dbPwd -W $dbPwd";
run_test($testname, $command);

#$testname = "Convert nss db  to Java keystore";
#$command = "$java -cp $classpath org.mozilla.jss.tests.NSS2JKS $keystore $dbPwd $configfile $dbPwd";
#run_test($testname, $command);


$testname = "List CA certs";
$command = "$java -cp $classpath org.mozilla.jss.tests.ListCACerts $testdir";
run_test($testname, $command);

updateCertSN();
$serverPort = checkPort($serverPort);
$testname = "SSLClientAuth";
$command = "$java -cp $classpath org.mozilla.jss.tests.SSLClientAuth $testdir $pwfile $serverPort $certSN";
run_test($testname, $command);


$testname = "Key Generation";
$command = "$java -ea -cp $classpath org.mozilla.jss.tests.TestKeyGen $testdir $pwfile";
run_test($testname, $command);

$testname = "Key Factory";
$command = "$java -cp $classpath org.mozilla.jss.tests.KeyFactoryTest $testdir $pwfile";
run_test($testname, $command);

$testname = "Digest";
$command = "$java -cp $classpath org.mozilla.jss.tests.DigestTest $testdir $pwfile";
run_test($testname, $command);

$testname = "HMAC ";
$command = "$java -cp $classpath org.mozilla.jss.tests.HMACTest $testdir $pwfile";
run_test($testname, $command);

$testname = "HMAC Unwrap";
$command = "$java -cp $classpath org.mozilla.jss.tests.HmacTest $testdir $pwfile";
run_test($testname, $command);

$testname = "KeyWrapping ";
$command = "$java -cp $classpath org.mozilla.jss.tests.JCAKeyWrap $testdir $pwfile";
run_test($testname, $command);

$testname = "Mozilla-JSS JCA Signature ";
$command = "$java -cp $classpath org.mozilla.jss.tests.JCASigTest $testdir $pwfile";
run_test($testname, $command);

$testname = "Mozilla-JSS NSS Signature ";
$command = "$java -cp $classpath org.mozilla.jss.tests.SigTest $testdir $pwfile";
run_test($testname, $command);

$testname = "JSS Signature test";
$command = "$java -cp $classpath org.mozilla.jss.tests.SigTest $testdir $pwfile";
run_test($testname, $command);

$testname = "Secret Decoder Ring";
$command = "$java -cp $classpath org.mozilla.jss.tests.TestSDR $testdir $pwfile";
run_test($testname, $command);

$testname = "List cert by certnick";
$command = "$java -cp $classpath org.mozilla.jss.tests.ListCerts $testdir Server_RSA";
run_test($testname, $command);

$testname = "Verify cert by certnick";
$command = "$java -cp $classpath org.mozilla.jss.tests.VerifyCert $testdir $pwfile Server_RSA";
run_test($testname, $command);

$testname = "Secret Key Generation";
$command = "$java -cp $classpath org.mozilla.jss.tests.SymKeyGen $testdir";
run_test($testname, $command);

$testname = "Mozilla-JSS Secret Key Generation";
$command = "$java -cp $classpath org.mozilla.jss.tests.JCASymKeyGen $testdir";
run_test($testname, $command);


#
# SSLServer and SSLClient Ciphersuite tests
#
# Servers are kicked off by the shell script and are told to shutdown by the client test
#

$serverPort = checkPort($serverPort);
$testname = "SSL Ciphersuite JSS Server and JSS client both";
$serverCommand = "$run_shell ./startJssSelfServ.$scriptext $classpath $testdir $hostname $serverPort  $java";
$command = "$java -cp $classpath org.mozilla.jss.tests.JSS_SelfServClient 2 -1 $testdir $pwfile $hostname $serverPort verboseoff JSS";
# To be restored when bug 1321594 is fixed
# run_ssl_test($testname, $serverCommand, $command);


$serverPort = checkPort($serverPort);
$testname = "SSL Ciphersuite JSS Server and JSSE client";
$serverCommand = "$run_shell ./startJssSelfServ.$scriptext $classpath $testdir $hostname $serverPort $java";
$command = "$java -cp $classpath org.mozilla.jss.tests.JSSE_SSLClient $testdir $serverPort $hostname JSS";
# To be restored when bug 1321594 is fixed
#run_ssl_test($testname, $serverCommand, $command);


$serverPort = checkPort($serverPort);
$testname = "SSL Ciphersuite JSSE Server using default provider and JSS client";
$serverCommand = "$run_shell ./startJsseServ.$scriptext $classpath $serverPort false $testdir rsa.pfx default $configfile $pwfile $java";
$command = "$java -cp $classpath org.mozilla.jss.tests.JSS_SelfServClient 2 -1 $testdir $pwfile $hostname $serverPort  verboseoff JSSE";
# To be restored when bug 1321594 is fixed
#run_ssl_test($testname, $serverCommand, $command);


if ($java_version =~ /1.4/i || $osname =~ /HP/ || ( ($osname =~ /Linux/)  && $java_version =~ /1.5/i && ($ENV{USE_64}) )) {
    print "don't run the SunJSSE with Mozilla-JSS provider with Java4 need java5 or higher";
    print "don't run the JSSE Server tests on HP or Linux  64 bit with java5.\n";
    print "Java 5 on HP does not have SunPKCS11 class\n";
} else {
#with JSS is being build with JDK 1.5 add the Sunpkcs11-NSS support back in!
#$serverPort = checkPort($serverPort);
#$testname = "SSL Ciphersuite JSSE Server using Sunpkcs11-NSS provider and JSS client";
#$serverCommand = "./startJsseServ.$scriptext $classpath $serverPort false $testdir rsa.pfx Sunpkcs11 $configfile $pwfile $java";
#$command = "$java -cp $classpath org.mozilla.jss.tests.JSS_SelfServClient 2 -1 $testdir $pwfile $hostname $serverPort  verboseoff JSSE";
#run_ssl_test($testname, $serverCommand, $command);

#$serverPort = checkPort($serverPort);
#$testname = "SSL Ciphersuite JSSE Server using Sunpkcs11-NSS provider and JSS client";
#$serverCommand = "./startJsseServ.$scriptext $classpath $serverPort false $testdir rsa.pfx Sunpkcs11 $configfile $pwfile $java";
#$command = "$java -cp $classpath org.mozilla.jss.tests.JSS_SelfServClient 2 -1 $testdir $pwfile $hostname $serverPort verboseoff JSSE";
#run_ssl_test($testname, $serverCommand, $command);

#Mozilla-JSS only works with JDK 1.5 or higher when used as provider for SunJSSE
$serverPort = checkPort($serverPort);
$testname = "SSL Ciphersuite JSSE Server using Mozilla-JSS provider and JSS client";
$serverCommand = "$run_shell ./startJsseServ.$scriptext $classpath $serverPort false $testdir rsa.pfx Mozilla-JSS $configfile $pwfile $java";
$command = "$java -cp $classpath org.mozilla.jss.tests.JSS_SelfServClient 2 -1 $testdir $pwfile $hostname $serverPort verboseoff Mozilla-JSS";
# To be restored when bug 1321594 is fixed
#run_ssl_test($testname, $serverCommand, $command);


}

#
# FIPSMODE tests
#

$testname = "Enable FipsMODE";
$command = "$java -cp $classpath org.mozilla.jss.tests.FipsTest $testdir enable";
run_test($testname, $command);

$testname = "check FipsMODE";
$command = "$java -cp $classpath org.mozilla.jss.tests.FipsTest $testdir chkfips";
run_test($testname, $command);

updateCertSN();
$testname = "SSLClientAuth FIPSMODE";
$serverPort = checkPort(++$serverPort);
$command = "$java -cp $classpath org.mozilla.jss.tests.SSLClientAuth $testdir $pwfile $serverPort $certSN";
run_test($testname, $command);

$testname = "HMAC FIPSMODE";
$command = "$java -cp $classpath org.mozilla.jss.tests.HMACTest $testdir $pwfile";
run_test($testname, $command);

$testname = "KeyWrapping FIPSMODE";
$command = "$java -cp $classpath org.mozilla.jss.tests.JCAKeyWrap $testdir $pwfile";
run_test($testname, $command);

$testname = "Mozilla-JSS JCA Signature FIPSMODE";
$command = "$java -cp $classpath org.mozilla.jss.tests.JCASigTest $testdir $pwfile";
run_test($testname, $command);

$testname = "JSS Signature test FipsMODE";
$command = "$java -cp $classpath org.mozilla.jss.tests.SigTest $testdir $pwfile";
run_test($testname, $command);

$serverPort = checkPort($serverPort);
$testname = "SSL Ciphersuite FIPSMODE JSS Server and JSS client both";
$serverCommand = "$run_shell ./startJssSelfServ.$scriptext $classpath $testdir $hostname $serverPort  $java";
$command = "$java -cp $classpath org.mozilla.jss.tests.JSS_SelfServClient 2 -1 $testdir $pwfile $hostname $serverPort  verboseoff JSS";
# To be restored when bug 1321594 is fixed
#run_ssl_test($testname, $serverCommand, $command);

$testname = "Disable FipsMODE";
$command = "$java -cp $classpath org.mozilla.jss.tests.FipsTest $testdir disable";
run_test($testname, $command);

if ($java_version =~ /1.8/i) {
    # Only run the PKCS11Constants test on JDK 8. Newer versions do not
    # expose the interface we are testing against.
    $testname = "Test PKCS11Constants.java for compatibility with Sun's interface";
    $command = "$java -ea -cp $classpath org.mozilla.jss.tests.TestPKCS11Constants";
    run_test($testname, $command);
}

$testname = "JSS DER Encoding of Enumeration regression test";
$command = "$java -cp $classpath org.mozilla.jss.tests.EnumerationZeroTest";
run_test($testname, $command);

#
# Test for JSS jar and library revision
#
$testname = "Check JSS jar version";
$command = "$java -cp $classpath org.mozilla.jss.tests.JSSPackageTest $testdir";
run_test($testname, $command);

my $LIB = "$lib_jss"."4"."$lib_suffix";
my $strings_exist = `which strings`;
chomp($strings_exist);
my $result = 0;
if ($strings_exist ne "") {
    (-f "$jss_lib_dir/$LIB") or die "$jss_lib_dir/$LIB does not exist\n";
    my $jsslibver = `strings $jss_lib_dir/$LIB | grep Header`;
    chomp($jsslibver);
    if ($jsslibver ne "") {
        print "$LIB = $jsslibver\n";
    } else {
        print "Could not fetch Header information from $jss_lib_dir/$LIB\n";
    }
} else {
    print "Could not fetch Header information from $jss_lib_dir/$LIB\n";
    $result = 1;
}

print "\n================= Test Results\n";
print "JSSTEST_SUITE: $testpass / $testrun\n";
my $rate = $testpass / $testrun * 100;
printf "JSSTEST_RATE: %.0f %%\n",$rate;

if ($testpass ne $testrun) {
    printf "Test Status: FAILURE\n";
    printf "to test failed tests set the classpath and run the command(s)\n";
    outputEnv();
    exit 1;
} else {
    printf "Test Status: SUCCESS\n";
    exit 0;
}
