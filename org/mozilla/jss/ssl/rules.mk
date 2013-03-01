# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

javadoc:
	@echo Steve's Javadoc rule -------------------------
	/usr/java/jdk1.1.5/bin/javadoc -sourcepath $(JAVA_HOME)/lib/classes.zip:$(CORE_DEPTH)/ninja -d /u/stevep/javadoc $(JSRCS)
	@echo End of Steve's Javadoc rule ------------------

runserver:
	$(DEBUG_CMD) $(SOURCE_BIN_DIR)/jssjava -classpath $(JAVA_HOME)/lib/classes.zip:$(SOURCE_CLASSES_DIR)_DBG org.mozilla.jss.ssl.SSLServer

runclient:
	$(DEBUG_CMD) $(SOURCE_BIN_DIR)/jssjava -classpath $(JAVA_HOME)/lib/classes.zip:$(SOURCE_CLASSES_DIR)_DBG org.mozilla.jss.ssl.SSLClient

debugcore:
	dbx $(SOURCE_BIN_DIR)/jssjava core
