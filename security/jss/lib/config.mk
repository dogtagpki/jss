# 
# The contents of this file are subject to the Mozilla Public
# License Version 1.1 (the "License"); you may not use this file
# except in compliance with the License. You may obtain a copy of
# the License at http://www.mozilla.org/MPL/
# 
# Software distributed under the License is distributed on an "AS
# IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
# implied. See the License for the specific language governing
# rights and limitations under the License.
# 
# The Original Code is the Netscape Security Services for Java.
# 
# The Initial Developer of the Original Code is Netscape
# Communications Corporation.  Portions created by Netscape are 
# Copyright (C) 1998-2000 Netscape Communications Corporation.  All
# Rights Reserved.
# 
# Contributor(s):
# 
# Alternatively, the contents of this file may be used under the
# terms of the GNU General Public License Version 2 or later (the
# "GPL"), in which case the provisions of the GPL are applicable 
# instead of those above.  If you wish to allow use of your 
# version of this file only under the terms of the GPL and not to
# allow others to use your version of this file under the MPL,
# indicate your decision by deleting the provisions above and
# replace them with the notice and other provisions required by
# the GPL.  If you do not delete the provisions above, a recipient
# may use your version of this file under either the MPL or the
# GPL.
# 

LIBRARY =

ifeq ($(OS_ARCH),WINNT)

SHARED_LIBRARY = $(OBJDIR)/$(LIBRARY_NAME)$(LIBRARY_VERSION).dll
IMPORT_LIBRARY = $(OBJDIR)/$(LIBRARY_NAME)$(LIBRARY_VERSION).lib

DLLFLAGS += -DEF:jss.def
#RES = $(OBJDIR)/jss.res
#RESNAME = jss.rc

SHARED_LIBRARY_LIBS=yes

SHARED_LIBRARY_DIRS = \
    ../org/mozilla/jss/crypto \
    ../org/mozilla/jss/manage \
    ../org/mozilla/jss/pkcs11 \
    ../org/mozilla/jss/ssl \
    ../org/mozilla/jss/util \
    ../org/mozilla/jss/hclhacks \
    $(NULL)

EXTRA_LIBS += \
    $(LIBNSS) \
    $(LIBSSL) \
    $(LIBCRYPTOHI) \
    $(LIBCERTHI) \
    $(LIBNSSB) \
    $(LIBPK11WRAP) \
    $(LIBJAR) \
    $(LIBPKCS12) \
    $(LIBPKCS7) \
    $(LIBSECTOOL) \
    $(LIBSMIME) \
    $(LIBSOFTOKEN) \
    $(LIBCERTDB) \
    $(LIBFREEBL) \
    $(LIBSECUTIL) \
    $(DIST)/lib/dbm.lib \
    $(NULL)

EXTRA_SHARED_LIBS += \
    $(DIST)/lib/$(NSPR31_LIB_PREFIX)plc4.lib \
    $(DIST)/lib/$(NSPR31_LIB_PREFIX)plds4.lib \
    $(DIST)/lib/$(NSPR31_LIB_PREFIX)nspr4.lib \
    $(JAVA_LIBS) \
    $(DLLSYSTEM) \
    $(NULL)

endif

ifeq ($(OS_ARCH),WINNT)
LDOPTS += -PDB:NONE
endif

# Include "funky" link path to pick up ALL native libraries for OSF/1.
ifeq ($(OS_ARCH), OSF1)
	JAVA_LIBS += -L$(JAVA_HOME)/$(JAVA_LIBDIR).no
endif
