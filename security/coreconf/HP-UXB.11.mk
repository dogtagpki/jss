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
# Config stuff for HP-UXB.11
#
include $(CORE_DEPTH)/coreconf/HP-UX.mk

ifdef USE_LONG_LONGS
USE_HYBRID = 1
endif

ifndef NS_USE_GCC
    CCC                 = /opt/aCC/bin/aCC -ext
    ifeq ($(USE_64), 1)
	OS_CFLAGS       +=  -Aa +e +DA2.0W +DS2.0 +DChpux
# Next line replaced by generic name handling in arch.mk
#	COMPILER_TAG    = _64
    else
	ifdef USE_HYBRID
	    OS_CFLAGS 	+= -Aa +e +DA2.0 +DS2.0 
	else
	    OS_CFLAGS   += +DAportable +DS2.0
	endif
    endif
else
    CCC = aCC
endif

OS_CFLAGS += -DHPUX11 
OS_LIBS   += -lpthread -lm -lrt
#ifeq ($(USE_64), 1)
#OS_LIBS   += -ldl
#else
#OS_LIBS   += -ldld
#endif
HPUX11	= 1
