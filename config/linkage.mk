# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

#######################################################################
# Adjust variables for component library linkage on some platforms    #
#######################################################################

#
# AIX platforms
#

ifeq ($(OS_ARCH),AIX)
	LDOPTS += -blibpath:.:$(PWD)/$(SOURCE_LIB_DIR):/usr/lib/threads:/usr/lpp/xlC/lib:/usr/lib:/lib 
endif

#
# HP/UX platforms
#

ifeq ($(OS_ARCH), HP-UX)
	LDOPTS += -Wl,+s,+b,$(PWD)/$(SOURCE_LIB_DIR)
endif

#
# IRIX platforms
#

ifeq ($(OS_ARCH), IRIX)
	LDOPTS += -rpath $(PWD)/$(SOURCE_LIB_DIR)
endif

#
# OSF 1 platforms
#

ifeq ($(OS_ARCH), OSF1)
	LDOPTS += -rpath $(PWD)/$(SOURCE_LIB_DIR) -lpthread
endif

#
# Solaris platforms
#     NOTE:  Disable optimization on SunOS4.1.3
#

ifeq ($(OS_ARCH), SunOS)
	ifneq ($(OS_RELEASE), 4.1.3_U1)
		ifdef NS_USE_GCC
			LDOPTS += -Xlinker -R -Xlinker $(PWD)/$(SOURCE_LIB_DIR)
		else
			LDOPTS += -R $(PWD)/$(SOURCE_LIB_DIR)
		endif
	else
		OPTIMIZER =
	endif
endif

#
# Windows platforms
#

ifeq ($(OS_ARCH), WINNT)
	LDOPTS    += -NOLOGO -DEBUG -DEBUGTYPE:CV -INCREMENTAL:NO
endif

