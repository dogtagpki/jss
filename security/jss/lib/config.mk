# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

LIBRARY =

SHARED_LIBRARY_LIBS=yes

SHARED_LIBRARY_DIRS = \
    ../org/mozilla/jss/crypto \
    ../org/mozilla/jss/SecretDecoderRing \
    ../org/mozilla/jss \
    ../org/mozilla/jss/pkcs11 \
    ../org/mozilla/jss/ssl \
    ../org/mozilla/jss/util \
    ../org/mozilla/jss/provider/java/security \
    $(NULL)
    
NSPR_LIB_NAMES = plc4 plds4 nspr4

NSS_LIB_NAMES = smime3 ssl3 nss3
ifdef USE_UTIL_DIRECTLY
NSS_LIB_NAMES += nssutil3
endif

ifeq ($(OS_ARCH),WINNT)

SHARED_LIBRARY = $(OBJDIR)/$(LIBRARY_NAME)$(LIBRARY_VERSION).dll
IMPORT_LIBRARY = $(OBJDIR)/$(LIBRARY_NAME)$(LIBRARY_VERSION).lib

DLLFLAGS += -DEF:jss.def
RES = $(OBJDIR)/jss.res
RESNAME = jss.rc

EXTRA_SHARED_LIBS += \
    $(addprefix $(NSS_LIB_DIR)/, $(addsuffix .$(LIB_SUFFIX), $(NSS_LIB_NAMES))) \
    $(addprefix $(NSPR_LIB_DIR)/$(NSPR31_LIB_PREFIX), $(addsuffix .$(LIB_SUFFIX), $(NSPR_LIB_NAMES))) \
    $(JAVA_LIBS) \
    $(DLLSYSTEM) \
    $(NULL)

else

ifeq ($(OS_ARCH),Darwin)
    DLL_SUFFIX = jnilib
endif

EXTRA_SHARED_LIBS += \
    -L$(NSS_LIB_DIR) \
    $(addprefix -l, $(NSS_LIB_NAMES)) \
    -L$(NSPR_LIB_DIR) \
    $(addprefix -l, $(NSPR_LIB_NAMES)) \
    $(JAVA_LIBS) \
    $(NULL)

endif

# Include "funky" link path to pick up ALL native libraries for OSF/1.
ifeq ($(OS_ARCH), OSF1)
	JAVA_LIBS += -L$(JAVA_HOME)/$(JAVA_LIBDIR).no
endif

ifeq ($(OS_ARCH),Linux)
MAPFILE = $(OBJDIR)/jssmap.linux
ALL_TRASH += $(MAPFILE)
MKSHLIB += -Wl,--version-script,$(MAPFILE)
endif

ifeq ($(OS_ARCH),SunOS)
MAPFILE = $(OBJDIR)/jssmap.sun
ALL_TRASH += $(MAPFILE)
MKSHLIB += -M $(MAPFILE)
#ifndef USE_64
#ifeq ($(CPU_ARCH),sparc)
# The -R '$ORIGIN' linker option instructs libnss3.so to search for its
# dependencies (libfreebl_*.so) in the same directory where it resides.
#MKSHLIB += -R '$$ORIGIN'
#endif
#endif
endif

ifeq ($(OS_ARCH),AIX)
MAPFILE = $(OBJDIR)/jssmap.aix
ALL_TRASH += $(MAPFILE)
EXPORT_RULES = -bexport:$(MAPFILE)
endif

ifeq ($(OS_ARCH),HP-UX)
MAPFILE = $(OBJDIR)/jssmap.hp
ALL_TRASH += $(MAPFILE)
MKSHLIB += -c $(MAPFILE)
endif

ifeq ($(OS_ARCH), OSF1)
MAPFILE = $(OBJDIR)/jssmap.osf
ALL_TRASH += $(MAPFILE)
MKSHLIB += -hidden -input $(MAPFILE)
endif
