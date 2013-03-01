#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
#ident	"$Id$"
#

CORE_DEPTH = ../../..

NAME        = sun-jss
ifndef RPM_RELEASE
RPM_RELEASE = 1
endif
VERSION     = `grep JSS_VERSION $(CORE_DEPTH)/jss/org/mozilla/jss/util/jssver.h \
		| sed -e 's/"$$//' -e 's/.*"//' -e 's/ .*//'`
PWD         = `pwd`
BUILDROOT   = $(PWD)\/$(NAME)-root

include $(CORE_DEPTH)/coreconf/config.mk

# Force i386 for non 64 bit build
ifneq ($(USE_64),1)
	RPMTARGET = "--target=i386"
	RPMLIBDIR = lib
else
	RPMLIBDIR = lib64
endif


publish:
	$(MAKE) clean
	mkdir -p SOURCES SRPMS RPMS BUILD
	mkdir -p opt/sun/private/$(RPMLIBDIR)
	find $(CORE_DEPTH)/../dist/$(OBJDIR)/lib -type l \
		\( -name "*jss*.so" \) \
	-exec cp {} opt/sun/private/$(RPMLIBDIR) \;
ifdef JSS3_LOCATION
	cp $(JSS3_LOCATION)/$(OBJDIR)/lib/libjss3.so opt/sun/private/$(RPMLIBDIR)
endif
	mkdir -p opt/sun/private/share/lib 
ifeq ($(BUILD_OPT), 1)
	cp $(CORE_DEPTH)/../dist/release/no-policy/classes/jss4.jar \
		opt/sun/private/share/lib/jss4.jar
ifdef JSS3_LOCATION
	cp $(JSS3_LOCATION)/xpclass.jar opt/sun/private/share/lib/jss3.jar
endif
else
	cp $(CORE_DEPTH)/../dist/release/no-policy/classes_DBG/jss4_dbg.jar \
		opt/sun/private/share/lib/jss4.jar
ifdef JSS3_LOCATION
	cp $(JSS3_LOCATION)/xpclass_dbg.jar opt/sun/private/share/lib/jss3.jar
endif
endif
	tar czvf $(NAME)-$(VERSION).tar.gz opt 
	echo "AutoReq: 0" > temp.spec
	echo "%define _topdir `pwd`" >>temp.spec
	sed -e "s/NAME_REPLACE/$(NAME)/" \
		-e "s/VERSION_REPLACE/$(VERSION)/" \
		-e "s/RELEASE_REPLACE/$(RPM_RELEASE)/" \
	<$(NAME).spec >>temp.spec
	echo "" >>temp.spec
	echo "%files" >>temp.spec
	echo "%defattr(-,root,root)" >>temp.spec
	echo "%dir /opt" >>temp.spec
	echo "%dir /opt/sun" >>temp.spec
	echo "%dir /opt/sun/private" >>temp.spec
	echo "%dir /opt/sun/private/$(RPMLIBDIR)" >>temp.spec
	echo "%dir /opt/sun/private/share" >>temp.spec
	echo "%dir /opt/sun/private/share/lib" >>temp.spec
	find opt \( -name "*.so" -o -name "*.jar" \) \
		| sed -e "s-^-/-" >>temp.spec
	echo "" >>temp.spec
	echo "%files devel" >>temp.spec
	echo "%defattr(-,root,root)" >>temp.spec
	find opt -type d | sed -e "s-^-%dir /-" >>temp.spec
	find opt -type f ! \( -name "*.so" -o -name "*.jar" \) \
		| sed -e "s-^-/-" >>temp.spec
	cp $(NAME)-$(VERSION).tar.gz SOURCES
	rpmbuild $(RPMTARGET) -bb temp.spec

clean::
	rm -rf SOURCES SRPMS RPMS BUILD
	rm -rf opt 
	rm -f temp.spec
	rm -f $(NAME)-$(VERSION).tar.gz

include $(CORE_DEPTH)/coreconf/rules.mk
