#
# Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"$Id$"
#

CORE_DEPTH = ../../..

NAME        = sun-jss
NAME3        = sun-jss3
RELEASE     = 1
VERSION     = `grep JSS_VERSION $(CORE_DEPTH)/jss/org/mozilla/jss/util/jssver.h \
		| sed -e 's/"$$//' -e 's/.*"//' -e 's/ .*//'`
PWD         = `pwd`
BUILDROOT   = $(PWD)\/$(NAME)-root

include $(CORE_DEPTH)/coreconf/config.mk

publish:
	$(MAKE) clean
	mkdir -p SOURCES SRPMS RPMS BUILD
	mkdir -p opt/sun/private/lib
	find $(CORE_DEPTH)/../dist/$(OBJDIR)/lib -type l \
		\( -name "*jss*.so" \) \
        -exec cp {} opt/sun/private/lib \;
#	(cd $(CORE_DEPTH)/../dist/public && tar cphf - .) \
#		| (mkdir -p opt/sun/private/include && cd opt/sun/private/include && tar xvfBp -)
	mkdir -p opt/sun/private/share/lib 
ifeq ($(BUILD_OPT), 1)
	cp $(CORE_DEPTH)/../dist/release/no-policy/classes/xpclass.jar \
		opt/sun/private/share/lib/jss3.jar
else
	cp $(CORE_DEPTH)/../dist/release/no-policy/classes_DBG/xpclass_dbg.jar \
		opt/sun/private/share/lib/jss3.jar
endif
	# sun-jss
	tar czvf $(NAME)-$(VERSION).tar.gz opt 
	cp $(NAME)-$(VERSION).tar.gz SOURCES
	echo "AutoReq: 0" > temp.spec
	echo "%define _topdir `pwd`" >>temp.spec
	sed -e "s/NAME_REPLACE/$(NAME)/" \
		-e "s/VERSION_REPLACE/$(VERSION)/" \
		-e "s/RELEASE_REPLACE/$(RELEASE)/" \
	<$(NAME).spec >>temp.spec
	echo "" >>temp.spec
	echo "%files" >>temp.spec
	echo "%defattr(-,root,root)" >>temp.spec
	echo "%dir /opt" >>temp.spec
	echo "%dir /opt/sun" >>temp.spec
	echo "%dir /opt/sun/private" >>temp.spec
	echo "%dir /opt/sun/private/lib" >>temp.spec
	find opt \( -name "*.so" -o -name "*.jar" \) \
		| sed -e "s-^-/-" >>temp.spec
	echo "" >>temp.spec
	echo "%files devel" >>temp.spec
	echo "%defattr(-,root,root)" >>temp.spec
	find opt -type d | sed -e "s-^-%dir /-" >>temp.spec
	find opt -type f ! \( -name "*.so" -o -name "*.jar" \) \
		| sed -e "s-^-/-" >>temp.spec
	(export LD_LIBRARY_PATH=$(CORE_DEPTH)/../dist/$(OBJDIR)/lib;\
	rpm -ba temp.spec)

	# sun-jss3
	tar czvf $(NAME3)-$(VERSION).tar.gz opt 
	cp $(NAME3)-$(VERSION).tar.gz SOURCES
	echo "AutoReq: 0" > temp3.spec
	echo "%define _topdir `pwd`" >>temp3.spec
	sed -e "s/NAME_REPLACE/$(NAME3)/" \
		-e "s/VERSION_REPLACE/$(VERSION)/" \
		-e "s/RELEASE_REPLACE/$(RELEASE)/" \
	<$(NAME3).spec >>temp3.spec
	echo "" >>temp3.spec
	echo "%files" >>temp3.spec
	echo "%defattr(-,root,root)" >>temp3.spec
	echo "%dir /opt" >>temp3.spec
	echo "%dir /opt/sun" >>temp3.spec
	echo "%dir /opt/sun/private" >>temp3.spec
	echo "%dir /opt/sun/private/lib" >>temp3.spec
	find opt \( -name "*.so" -o -name "*.jar" \) \
		| sed -e "s-^-/-" >>temp3.spec
	echo "" >>temp3.spec
	echo "%files devel" >>temp3.spec
	echo "%defattr(-,root,root)" >>temp3.spec
	find opt -type d | sed -e "s-^-%dir /-" >>temp3.spec
	find opt -type f ! \( -name "*.so" -o -name "*.jar" \) \
		| sed -e "s-^-/-" >>temp3.spec
    
	(export LD_LIBRARY_PATH=$(CORE_DEPTH)/../dist/$(OBJDIR)/lib;\
	rpm -ba temp3.spec)

clean::
	rm -rf SOURCES SRPMS RPMS BUILD
	rm -rf opt 
	rm -f temp.spec
	rm -f $(NAME)-$(VERSION).tar.gz
	rm -f $(NAME3)-$(VERSION).tar.gz

include $(CORE_DEPTH)/coreconf/rules.mk
