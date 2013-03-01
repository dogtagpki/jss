# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

#
# Configuration information unique to the "sectools" component
#


#######################################################################
#  Local "sectools" component library link options                    #
#######################################################################

include $(CORE_DEPTH)/$(MODULE)/config/linkage.mk

#######################################################################
#  Local "sectools" component STATIC system library names             #
#######################################################################

include $(CORE_DEPTH)/$(MODULE)/config/static.mk

#######################################################################
#  Local "sectools" component DYNAMIC system library names            #
#######################################################################

include $(CORE_DEPTH)/$(MODULE)/config/dynamic.mk

# Stricter semantic checking for SunOS compiler. This catches calling
# undeclared functions, a major headache during debugging.
ifeq ($(OS_ARCH), SunOS)
    OS_CFLAGS += -v
endif

ifeq ($(OS_ARCH), WINNT)
LINK_DLL += -LIBPATH:$(SOURCE_LIB_DIR)
LINK_DLL += -LIBPATH:$(JAVA_HOME)/$(JAVA_LIBDIR)
LINK_DLL += $(foreach file,$(LD_LIBS),-DEFAULTLIB:"$(notdir $(file))")
endif

CFLAGS += -I$(JAVA_HOME)/include
