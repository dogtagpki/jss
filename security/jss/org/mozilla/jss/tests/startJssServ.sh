#!/bin/sh 
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
 
######################################################################## 
# 
# "Starting JSS JAA_SSLServer..." 
# 
JSS_CLASSPATH=$1
TESTDIR=$2
Port=$3
Bypass=$4
FipsMode=$5
shift 5 
JAVA_BIN_AND_OPT=$@

if [ -z "$JAVA_BIN_AND_OPT" ] ;
then
  JAVA_BIN_AND_OPT=${JAVA_HOME}/bin/java
fi

${JAVA_BIN_AND_OPT} -classpath ${JSS_CLASSPATH} org.mozilla.jss.tests.JSS_SSLServer ${TESTDIR} passwords localhost JSSTestServerCert true ${Port} ${Bypass} ${FipsMode} & 

