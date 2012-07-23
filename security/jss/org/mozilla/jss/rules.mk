# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

JAVADOC_TARGETS=                                                        \
                    org.mozilla.jss                                     \
                    org.mozilla.jss.asn1                                \
                    org.mozilla.jss.crypto                              \
                    org.mozilla.jss.pkcs7                               \
                    org.mozilla.jss.pkcs10                              \
                    org.mozilla.jss.pkcs11                              \
                    org.mozilla.jss.pkcs12                              \
                    org.mozilla.jss.pkix.primitive                      \
                    org.mozilla.jss.pkix.cert                           \
                    org.mozilla.jss.pkix.cmc                            \
                    org.mozilla.jss.pkix.cmmf                           \
                    org.mozilla.jss.pkix.cms                            \
                    org.mozilla.jss.pkix.crmf                           \
                    org.mozilla.jss.provider                            \
                    org.mozilla.jss.ssl                                 \
                    org.mozilla.jss.tests                               \
                    org.mozilla.jss.util                                \
                    $(NULL)

ifneq ($(HTML_HEADER),)
HTML_HEADER_OPT=-header '$(HTML_HEADER)'
endif

javadoc:
	cp -i manage/*.java .
	if [ ! -d "$(DIST)/jssdoc" ] ; then mkdir -p $(CORE_DEPTH)/jssdoc ; fi
	$(JAVADOC) -native -private -sourcepath $(CORE_DEPTH)/jss -d $(CORE_DEPTH)/jssdoc $(HTML_HEADER_OPT) $(JAVADOC_TARGETS)
	rm -i *.java
