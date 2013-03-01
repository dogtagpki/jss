# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

#######################################################################
# Adjust specific variables for specific platforms                    #
#######################################################################

ifeq ($(OS_ARCH), HP-UX)
	DEFINES += -D_ILP32
endif
TARGETS=$(LIBRARY)
SHARED_LIBRARY=
IMPORT_LIBRARY=

NO_MD_RELEASE = 1
