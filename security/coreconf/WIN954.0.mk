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
# The Original Code is the Netscape security libraries.
# 
# The Initial Developer of the Original Code is Netscape
# Communications Corporation.  Portions created by Netscape are 
# Copyright (C) 1994-2000 Netscape Communications Corporation.  All
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

#
# Config stuff for WIN95
#
# This makefile defines the following variables:
# CPU_ARCH, OS_CFLAGS, and OS_DLLFLAGS.
# PROCESSOR is an internal variable.

include $(CORE_DEPTH)/coreconf/WIN32.mk

PROCESSOR := $(shell uname -p)
ifeq ($(PROCESSOR), I386)
	CPU_ARCH   = x386
	OS_CFLAGS += -W3 -nologo
	DEFINES += -D_X86_
else 
	ifeq ($(PROCESSOR), MIPS)
		CPU_ARCH    = MIPS
		#OS_CFLAGS += -W3 -nologo
		#DEFINES += -D_MIPS_
		OS_CFLAGS  += -W3 -nologo
	else 
		ifeq ($(PROCESSOR), ALPHA)
			CPU_ARCH  = ALPHA
			OS_CFLAGS += -W3 -nologo
			DEFINES += -D_ALPHA_=1
		else 
			CPU_ARCH  = processor_is_undefined
		endif
	endif
endif

OS_DLLFLAGS += -nologo -DLL -SUBSYSTEM:WINDOWS -PDB:NONE
DEFINES += -DWIN95
