# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

#######################################################################
# Initialize DYNAMIC system library names on some platforms           #
#######################################################################

#
# AIX platforms
#


ifeq ($(OS_ARCH),AIX)
ifeq ($(OS_RELEASE),4.1)
	DLLSYSTEM += -lsvld -lC_r -lC -lpthreads -lc_r -lm /usr/lib/libc.a
else
	DLLSYSTEM += -ldl -lC_r -lC -lpthreads -lc_r -lm /usr/lib/libc.a
endif
endif

#
# HP/UX platforms
#

ifeq ($(OS_ARCH),HP-UX)
	ifeq ($(USE_PTHREADS), 1)
		DLLSYSTEM += -lpthread
	endif
	ifeq ($(PTHREADS_USER), 1)
		DLLSYSTEM += -lpthread
	endif
	ifeq ($(OS_RELEASE),A.09.03)
		DLLSYSTEM += -ldld -L/lib/pa1.1 -lm
	else
		DLLSYSTEM += -ldld -lm -lc 
	endif
endif

#
# IRIX platforms
#

ifeq ($(OS_ARCH), IRIX)
	ifeq ($(USE_PTHREADS), 1)
		DLLSYSTEM += -lpthread
	endif
endif

#
# Linux platforms
#

ifeq ($(OS_ARCH), Linux)
	DLLSYSTEM += -ldl -lpthread -lm
endif

#
# NCR platforms
#

ifeq ($(OS_ARCH), NCR)
	DLLSYSTEM += -lsocket -ldl -lnsl -lc
endif

#
# OSF 1 platforms
#

ifeq ($(OS_ARCH),OSF1)
	ifneq ($(OS_RELEASE),V2.0)
		DLLSYSTEM += -lc_r
	endif
	ifeq ($(USE_PTHREADS), 1)
		DLLSYSTEM += -lpthread -lrt
	endif
	ifeq ($(USE_IPV6), 1)
		DLLSYSTEM += -lip6
	endif
endif

#
# SCO platforms
#

ifeq ($(OS_ARCH), SCO_SV)
	DLLSYSTEM += -lsocket -ldl -lnsl -lc
endif

#
# Solaris platforms
#

ifeq ($(OS_ARCH), SunOS)
	ifneq ($(OS_RELEASE), 4.1.3_U1)
		DLLSYSTEM += -lthread -lposix4 -lsocket -lnsl -lintl -ldl
	endif
endif

#
# UNIXWARE platforms
#

ifeq ($(OS_ARCH), UNIXWARE)
	DLLSYSTEM += -lsocket
endif

#
# Windows platforms
#

ifeq ($(OS_ARCH),WINNT)
	ifneq ($(OS_TARGET),WIN16)
		DLLSYSTEM += wsock32.lib winmm.lib
	endif
endif

