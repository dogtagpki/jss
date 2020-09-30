#!/bin/sh
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

########################################################################
#
# "Starting JSSE JSSE_SSLServer Test..."
# 
JSS_CLASSPATH=$1
Port=$2
ClientAuth=$3
TestDir=$4
dbFile=$5
provider=$6
nssConfigFile=$7
nssPWFile=$8
shift 8 
JAVA_BIN_AND_OPT=$@

if [ -z "$JAVA_BIN_AND_OPT" ] ;
then
  JAVA_BIN_AND_OPT=${JAVA_HOME}/bin/java
fi

#echo "command"
#echo "JSS_CLASSPATH=${JSS_CLASSPATH}"
#echo "Port=${Port}"
#echo "ClientAuth=${ClientAuth}"
#echo "TestDir=${TestDir}"
#echo "dbFile=${dbFile}"
#echo "provider=${provider}"
#echo "nssConfigFile=${nssConfigFile}"
#echo "nssPWFile=${nssPWFile}"
#echo "JAVA_BIN_AND_OPT=${JAVA_BIN_AND_OPT}"

echo "${JAVA_BIN_AND_OPT} -classpath ${JSS_CLASSPATH} org.mozilla.jss.tests.JSSE_SSLServer ${Port} TLS ${ClientAuth} ${TestDir} ${dbFile} ${provider} ${nssConfigFile} ${nssPWFile}&"
echo "command"
${JAVA_BIN_AND_OPT} -classpath ${JSS_CLASSPATH} org.mozilla.jss.tests.JSSE_SSLServer ${Port} TLS ${ClientAuth} ${TestDir} ${dbFile} ${provider} ${nssConfigFile} ${nssPWFile}&

