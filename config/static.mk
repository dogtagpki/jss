# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

#######################################################################
# Initialize STATIC system library names on some platforms            #
#######################################################################

#
# AIX platforms
#

ifeq ($(OS_ARCH),AIX)
ifeq ($(OS_RELEASE),4.1)	
	LIBSYSTEM += /lib/libsvld.a /lib/libC_r.a /lib/libC.a /lib/libpthreads.a /lib/libc_r.a /lib/libm.a /lib/libc.a
else 
	LIBSYSTEM += -ldl /lib/libC_r.a /lib/libC.a /lib/libpthreads.a /lib/libc_r.a /lib/libm.a /lib/libc.a
	endif
endif


#
# HP/UX platforms
#

ifeq ($(OS_ARCH),HP-UX)
	ifeq ($(USE_PTHREADS), 1)
		LIBSYSTEM += -lpthread
	endif
	ifeq ($(PTHREADS_USER), 1)
		LIBSYSTEM += -lpthread
	endif
	ifeq ($(OS_RELEASE),A.09.03)
		LIBSYSTEM += -ldld -L/lib/pa1.1 -lm
	else
		LIBSYSTEM += -ldld -lm -lc 
	endif
endif

#
# Linux platforms
#

ifeq ($(OS_ARCH), Linux)
	LIBSYSTEM += -ldl
endif

#
# IRIX platforms
#

ifeq ($(OS_ARCH), IRIX)
	ifeq ($(USE_PTHREADS), 1)
		LIBSYSTEM += -lpthread
	endif
endif

#
# OSF 1 platforms
#

ifeq ($(OS_ARCH),OSF1)
	ifneq ($(OS_RELEASE),V2.0)
		LIBSYSTEM += -lc_r
	endif
	ifeq ($(USE_PTHREADS), 1)
		LIBSYSTEM += -lpthread -lrt
	endif
	ifeq ($(USE_IPV6), 1)
		LIBSYSTEM += -lip6
	endif
endif

#
# Solaris platforms
#

ifeq ($(OS_ARCH), SunOS)
	ifneq ($(OS_RELEASE), 4.1.3_U1)
		ifeq ($(OS_RELEASE), 5.5.1_i86pc)
			LIBSYSTEM += -lsocket -lnsl -lintl -ldl
		else
			ifeq ($(OS_RELEASE), 5.6_i86pc)
				LIBSYSTEM += -lsocket -lnsl -lintl -ldl
			else
				LIBSYSTEM += -lthread -lposix4 /lib/libsocket.a /lib/libnsl.a /lib/libintl.a -ldl
			endif
		endif
	endif
endif

#
# UNIXWARE platforms
#

ifeq ($(OS_ARCH), UNIXWARE)
	LIBSYSTEM += -lsocket
endif

#
# Windows platforms
#

ifeq ($(OS_ARCH),WINNT)
	ifneq ($(OS_TARGET),WIN16)
		LIBSYSTEM += wsock32.lib winmm.lib
	endif
endif

