#
# Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"$Id$"
#

CORE_DEPTH = ../../..

%: %.ksh
	$(RM) $@
	cp $< $@
	chmod +x $@


ifeq ($(USE_64), 1)
DIRS = \
    SUNWjssx
else
DIRS = \
    SUNWjss
endif

PROTO = \
	$(ROOT) \
	$(ROOT)/usr \
	$(ROOT)/usr/lib \
	$(ROOT)/usr/lib/mps

ifdef USE_64
PROTO += $(ROOT)/usr/lib/mps/sparcv9
endif

include Makefile.com

awk_pkginfo: bld_awk_pkginfo
	./bld_awk_pkginfo -m $(MACH) -p "$(PRODUCT_VERSION)" -o $@ -v $(PRODUCT_VERSION)

all:: awk_pkginfo $(PROTO)
publish: awk_pkginfo $(PROTO)
	+$(LOOP_OVER_DIRS)

clean clobber::
	$(RM) awk_pkginfo bld_awk_pkginfo
	$(RM) -r $(ROOT)

$(ROOT) $(ROOT)/%:
	mkdir -p $@

ifdef USE_64
$(ROOT)/usr/lib/mps/sparcv9: $(ROOT)/usr/lib
	$(LN) -sf ../../../../$(DIST)/lib $@
../../../../$(DIST)/lib/jss32.jar: $(IMPORT_XPCLASS_DIR)/$(SOURCE_RELEASE_XP_CLASSES_DIR)/$(IMPORT_XPCLASS_JAR)
	$(LN) -sf $(IMPORT_XPCLASS_DIR)/$(SOURCE_RELEASE_XP_CLASSES_DIR)/$(IMPORT_XPCLASS_JAR) $@
else
$(ROOT)/usr/lib/mps: $(ROOT)/usr/lib
	echo "target=$(SOURCE_RELEASE_XP_DIR)/$(SOURCE_RELEASE_XP_CLASSES_DIR)/$(IMPORT_XPCLASS_JAR)"
	$(LN) -sf ../../../$(DIST)/lib $@
#	$(LN) -sf $(SOURCE_RELEASE_XP_DIR)/$(SOURCE_RELEASE_XP_CLASSES_DIR)/$(IMPORT_XPCLASS_JAR) $(ROOT)/usr/lib/mps/jss32.jar
	cp $(SOURCE_RELEASE_XP_DIR)/$(SOURCE_RELEASE_XP_CLASSES_DIR)/$(IMPORT_XPCLASS_JAR) $(ROOT)/usr/lib/mps/jss32.jar

#$(ROOT)/usr/lib/mps/jss32.jar: $(SOURCE_RELEASE_XP_DIR)/$(SOURCE_RELEASE_XP_CLASSES_DIR)/$(IMPORT_XPCLASS_JAR) 
#$(ROOT)/usr/lib/mps/jss32.jar: $(ROOT)/usr/lib/mps
#	$(LN) -sf $(SOURCE_RELEASE_XP_DIR)/$(SOURCE_RELEASE_XP_CLASSES_DIR)/$(IMPORT_XPCLASS_JAR) $@
endif
