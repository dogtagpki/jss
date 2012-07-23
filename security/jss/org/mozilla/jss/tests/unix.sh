# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

#!/usr/bin/tcsh


if ( `uname` == "AIX" ) then



	setenv LIBPATH ../../../../../dist/AIX4.2_DBG.OBJ/lib:/share/builds/components/jdk/1.1.6/AIX/lib/aix/native_threads
	echo Testing \"jssjava\" on `uname` `uname -v`.`uname -r` DBG platform . . .
	../../../../../dist/AIX4.2_DBG.OBJ/bin/jssjava -classpath ../../../../../dist/classes_DBG:/share/builds/components/jdk/1.1.6/AIX/lib/classes.zip org.mozilla.jss.crypto.PQGGen 512
	echo Testing \"jssjava_g\" on `uname` `uname -v`.`uname -r` DBG platform . . .
	../../../../../dist/AIX4.2_DBG.OBJ/bin/jssjava_g -classpath ../../../../../dist/classes_DBG:/share/builds/components/jdk/1.1.6/AIX/lib/classes.zip org.mozilla.jss.crypto.PQGGen 512


	setenv LIBPATH ../../../../../dist/AIX4.2_OPT.OBJ/lib:/share/builds/components/jdk/1.1.6/AIX/lib/aix/native_threads
	echo Testing \"jssjava\" on `uname` `uname -v`.`uname -r` OPT platform . . .
	../../../../../dist/AIX4.2_OPT.OBJ/bin/jssjava -classpath ../../../../../dist/classes:/share/builds/components/jdk/1.1.6/AIX/lib/classes.zip org.mozilla.jss.crypto.PQGGen 512





else if ( `uname` == "HP-UX" ) then


	setenv SHLIB_PATH ../../../../../dist/HP-UXB.11.00_DBG.OBJ/lib:/share/builds/components/jdk/1.1.5/HP-UX/lib/PA_RISC/native_threads
	echo Testing \"jssjava\" on `uname` `uname -r` DBG platform . . .
	../../../../../dist/HP-UXB.11.00_DBG.OBJ/bin/jssjava -classpath ../../../../../dist/classes_DBG:/share/builds/components/jdk/1.1.5/HP-UX/lib/classes.zip org.mozilla.jss.crypto.PQGGen 512
	echo Testing \"jssjava_g\" on `uname` `uname -r` DBG platform . . .
	../../../../../dist/HP-UXB.11.00_DBG.OBJ/bin/jssjava_g -classpath ../../../../../dist/classes_DBG:/share/builds/components/jdk/1.1.5/HP-UX/lib/classes.zip org.mozilla.jss.crypto.PQGGen 512


	setenv SHLIB_PATH ../../../../../dist/HP-UXB.11.00_OPT.OBJ/lib:/share/builds/components/jdk/1.1.5/HP-UX/lib/PA_RISC/native_threads
	echo Testing \"jssjava\" on `uname` `uname -r` OPT platform . . .
	../../../../../dist/HP-UXB.11.00_OPT.OBJ/bin/jssjava -classpath ../../../../../dist/classes:/share/builds/components/jdk/1.1.5/HP-UX/lib/classes.zip org.mozilla.jss.crypto.PQGGen 512





else if ( ( `uname` == "IRIX" ) || ( `uname` == "IRIX64" ) ) then


	setenv LD_LIBRARY_PATH ../../../../../dist/IRIX6.2_PTH_DBG.OBJ/lib:/share/builds/components/jdk/1.1.5/IRIX/lib32/sgi/native_threads
	echo Testing \"jssjava\" on `uname` `uname -r` DBG platform . . .
	../../../../../dist/IRIX6.2_PTH_DBG.OBJ/bin/jssjava -classpath ../../../../../dist/classes_DBG:/share/builds/components/jdk/1.1.5/IRIX/lib/rt.jar org.mozilla.jss.crypto.PQGGen 512
	echo Testing \"jssjava_g\" on `uname` `uname -r` DBG platform . . .
	../../../../../dist/IRIX6.2_PTH_DBG.OBJ/bin/jssjava_g -classpath ../../../../../dist/classes_DBG:/share/builds/components/jdk/1.1.5/IRIX/lib/rt.jar org.mozilla.jss.crypto.PQGGen 512


	setenv LD_LIBRARY_PATH ../../../../../dist/IRIX6.2_PTH_OPT.OBJ/lib:/share/builds/components/jdk/1.1.5/IRIX/lib32/sgi/native_threads
	echo Testing \"jssjava\" on `uname` `uname -r` OPT platform . . .
	../../../../../dist/IRIX6.2_PTH_OPT.OBJ/bin/jssjava -classpath ../../../../../dist/classes:/share/builds/components/jdk/1.1.5/IRIX/lib/rt.jar org.mozilla.jss.crypto.PQGGen 512





else if ( `uname` == "OSF1" ) then


	setenv LD_LIBRARY_PATH ../../../../../dist/OSF1V4.0D_DBG.OBJ/lib:/share/builds/components/jdk/1.1.6/OSF1/lib/alpha
	echo Testing \"jssjava\" on `uname` `uname -r`D DBG platform . . .
	../../../../../dist/OSF1V4.0D_DBG.OBJ/bin/jssjava -classpath ../../../../../dist/classes_DBG:/share/builds/components/jdk/1.1.5/OSF1/lib/classes.zip org.mozilla.jss.crypto.PQGGen 512
	echo Testing \"jssjava_g\" on `uname` `uname -r`D DBG platform . . .
	../../../../../dist/OSF1V4.0D_DBG.OBJ/bin/jssjava_g -classpath ../../../../../dist/classes_DBG:/share/builds/components/jdk/1.1.5/OSF1/lib/classes.zip org.mozilla.jss.crypto.PQGGen 512


	setenv LD_LIBRARY_PATH ../../../../../dist/OSF1V4.0D_OPT.OBJ/lib:/share/builds/components/jdk/1.1.6/OSF1/lib/alpha
	echo Testing \"jssjava\" on `uname` `uname -r`D OPT platform . . .
	../../../../../dist/OSF1V4.0D_OPT.OBJ/bin/jssjava -classpath ../../../../../dist/classes:/share/builds/components/jdk/1.1.5/OSF1/lib/classes.zip org.mozilla.jss.crypto.PQGGen 512





else if ( ( `uname` == "SunOS" ) && ( `uname -r` == "5.5.1" ) ) then

	setenv LD_LIBRARY_PATH ../../../../../dist/SunOS5.5.1_DBG.OBJ/lib:/share/builds/components/jdk/1.1.6/SunOS/lib/sparc/native_threads
	echo Testing \"jssjava\" on `uname` `uname -r` DBG platform . . .
	../../../../../dist/SunOS5.5.1_DBG.OBJ/bin/jssjava -classpath ../../../../../dist/classes_DBG:/share/builds/components/jdk/1.1.6/SunOS/lib/classes.zip org.mozilla.jss.crypto.PQGGen 512
	echo Testing \"jssjava_g\" on `uname` `uname -r` DBG platform . . .
	../../../../../dist/SunOS5.5.1_DBG.OBJ/bin/jssjava_g -classpath ../../../../../dist/classes_DBG:/share/builds/components/jdk/1.1.6/SunOS/lib/classes.zip org.mozilla.jss.crypto.PQGGen 512


	setenv LD_LIBRARY_PATH ../../../../../dist/SunOS5.5.1_OPT.OBJ/lib:/share/builds/components/jdk/1.1.6/SunOS/lib/sparc/native_threads
	echo Testing \"jssjava\" on `uname` `uname -r` OPT platform . . .
	../../../../../dist/SunOS5.5.1_OPT.OBJ/bin/jssjava -classpath ../../../../../dist/classes:/share/builds/components/jdk/1.1.6/SunOS/lib/classes.zip org.mozilla.jss.crypto.PQGGen 512





else if ( ( `uname` == "SunOS" ) && ( `uname -r` == "5.6" ) ) then

	setenv LD_LIBRARY_PATH ../../../../../dist/SunOS5.6_DBG.OBJ/lib:/share/builds/components/jdk/1.1.6/SunOS/lib/sparc/native_threads
	echo Testing \"jssjava\" on `uname` `uname -r` DBG platform . . .
	../../../../../dist/SunOS5.6_DBG.OBJ/bin/jssjava -classpath ../../../../../dist/classes_DBG:/share/builds/components/jdk/1.1.6/SunOS/lib/classes.zip org.mozilla.jss.crypto.PQGGen 512
	echo Testing \"jssjava_g\" on `uname` `uname -r` DBG platform . . .
	../../../../../dist/SunOS5.6_DBG.OBJ/bin/jssjava_g -classpath ../../../../../dist/classes_DBG:/share/builds/components/jdk/1.1.6/SunOS/lib/classes.zip org.mozilla.jss.crypto.PQGGen 512


	setenv LD_LIBRARY_PATH ../../../../../dist/SunOS5.6_OPT.OBJ/lib:/share/builds/components/jdk/1.1.6/SunOS/lib/sparc/native_threads
	echo Testing \"jssjava\" on `uname` `uname -r` OPT platform . . .
	../../../../../dist/SunOS5.6_OPT.OBJ/bin/jssjava -classpath ../../../../../dist/classes:/share/builds/components/jdk/1.1.6/SunOS/lib/classes.zip org.mozilla.jss.crypto.PQGGen 512





endif

