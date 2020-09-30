#! /bin/bash

##############################################################################
# Update java-1.8.0-openjdk to the latest and then do
# sudo /usr/sbin/alternatives --config java and hit enter
#
# For example, to check/select your Java version on Linux:
#
# sudo /usr/sbin/alternatives --config java
#
#  There is 1 program that provides 'java'.
#
#    Selection    Command
#  -----------------------------------------------
#  *+ 1           java-1.8.0-openjdk.x86_64 (/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.111-3.b16.fc24.x86_64/jre/bin/java)
#
# Hit Enter to keep the current selection[+], or type selection number:
#
# You may have multiple entries (like on RHEl-7.x) or only one
# This is for linux.  On macOS you'll have something like this
# JAVA_HOME_64=/Library/Java/JavaVirtualMachines/jdk1.8.0_65.jdk/Contents/Home
#
##############################################################################

# Each buildbot-slave requires a bbenv.sh file that defines
# machine specific variables. This is an example file.


HOST=$(hostname | cut -d. -f1)
export HOST

# if your machine's IP isn't registered in DNS,
# you must set appropriate environment variables
# that can be resolved locally.
# For example, if localhost.localdomain works on your system, set:
DOMSUF=localdomain
export DOMSUF

ARCH=$(uname -s)

ulimit -c unlimited 2> /dev/null

export NSPR_LOG_MODULES="pkix:1"

#export JAVA_HOME_32=
#export JAVA_HOME_64=

#enable if you have PKITS data
export PKITS_DATA=$HOME/pkits/

NSS_BUILD_TARGET="clean nss_build_all"
JSS_BUILD_TARGET="clean all"

MAKE=make
AWK=awk
PATCH=patch

if [ "${ARCH}" = "SunOS" ]; then
    AWK=nawk
    PATCH=gpatch
    ARCH=SunOS/$(uname -p)
fi

if [ "${ARCH}" = "Linux" -a -f /etc/system-release ]; then
  #VERSION=`sed -e 's; release ;;' -e 's; (.*)$;;' -e 's;Red Hat Enterprise Linux Server;RHEL;' -e 's;Red Hat Enterprise Linux Workstation;RHEL;' /etc/system-release`
   VERSION=$(uname -r | awk -F"." '{ print $1 "." $2 }')
   ARCH=Linux/4.8
   echo ${ARCH}
fi

PROCESSOR=$(uname -p)
if [ "${PROCESSOR}" = "ppc64" ]; then
    ARCH="${ARCH}/ppc64"
fi
if [ "${PROCESSOR}" = "powerpc" ]; then
    ARCH="${ARCH}/ppc"
fi

PORT_64_DBG=8543
PORT_64_OPT=8544
PORT_32_DBG=8545
PORT_32_OPT=8546

if [ "${NSS_TESTS}" = "memleak" ]; then
    PORT_64_DBG=8547
    PORT_64_OPT=8548
    PORT_32_DBG=8549
    PORT_32_OPT=8550
fi

# change to suit your environent, refer to the instructions on how to do it 
# at the top of this file
JAVA_HOME_64=/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.111-3.b16.fc25.x86_64

export NSS_FORCE_FIPS=1


