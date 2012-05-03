#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

SOL_CFLAGS	= -D_SVID_GETTOD

include $(CORE_DEPTH)/coreconf/SunOS5.mk

CPU_ARCH		= x86
ARCHFLAG		=
OS_DEFINES		+= -Di386

ifeq ($(OS_RELEASE),5.7_i86pc)
	OS_DEFINES += -DSOLARIS2_7
endif

OS_LIBS += -lthread -lnsl -lsocket -lposix4 -ldl -lc
