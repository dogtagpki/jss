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

#######################################################################
# Master <component>-specific source import/export directories        #
#######################################################################

#
# <user_source_tree> master import/export directory prefix
#

ifdef MOZILLA_CLIENT
SOURCE_PREFIX = $(MOD_DEPTH)/../../dist
else # !MOZILLA_CLIENT
SOURCE_PREFIX = $(MOD_DEPTH)/../dist
endif # MOZILLA_CLIENT

#
# <user_source_tree> cross-platform (xp) master import/export directory
#

SOURCE_XP_DIR        = $(SOURCE_PREFIX)

#
# <user_source_tree> cross-platform (xp) import/export directories
#

SOURCE_CLASSES_DIR     = $(SOURCE_XP_DIR)/classes
SOURCE_CLASSES_DBG_DIR = $(SOURCE_XP_DIR)/classes_DBG
SOURCE_XPHEADERS_DIR   = $(SOURCE_XP_DIR)/public/$(MODULE)
SOURCE_XPPRIVATE_DIR   = $(SOURCE_XP_DIR)/private/$(MODULE)

ifdef BUILD_OPT
	IMPORT_XPCLASS_DIR = $(SOURCE_CLASSES_DIR)
else
	IMPORT_XPCLASS_DIR = $(SOURCE_CLASSES_DBG_DIR)
endif

#
# <user_source_tree> machine-dependent (md) master import/export directory
#

SOURCE_MD_DIR        = $(SOURCE_PREFIX)/$(PLATFORM)

#
# <user_source_tree> machine-dependent (md) import/export directories
#

SOURCE_BIN_DIR       = $(SOURCE_MD_DIR)/bin
SOURCE_LIB_DIR       = $(SOURCE_MD_DIR)/lib
SOURCE_MDHEADERS_DIR = $(SOURCE_MD_DIR)/include

#######################################################################
# Master <component>-specific source release directories and files    #
#######################################################################

#
# <user_source_tree> cross-platform (xp) source-side master release directory
#

SOURCE_RELEASE_XP_DIR = $(SOURCE_RELEASE_PREFIX)

#
# <user_source_tree> cross-platform (xp) source-side release directories
#

SOURCE_RELEASE_CLASSES_DIR     = classes
SOURCE_RELEASE_CLASSES_DBG_DIR = classes_DBG
SOURCE_RELEASE_XPHEADERS_DIR   = include

#
# <user_source_tree> cross-platform (xp) JAR source-side release files
#

XPCLASS_JAR     = xpclass.jar
XPCLASS_DBG_JAR = xpclass_dbg.jar
XPHEADER_JAR    = xpheader.jar

ifdef BUILD_OPT
	IMPORT_XPCLASS_JAR = $(XPCLASS_JAR)
else
	IMPORT_XPCLASS_JAR = $(XPCLASS_DBG_JAR)
endif

#
# <user_source_tree> machine-dependent (md) source-side master release directory
#

SOURCE_RELEASE_MD_DIR = $(PLATFORM)

#
# <user_source_tree> machine-dependent (md) source-side release directories
#

SOURCE_RELEASE_BIN_DIR       = $(PLATFORM)/bin
SOURCE_RELEASE_LIB_DIR       = $(PLATFORM)/lib
SOURCE_RELEASE_MDHEADERS_DIR = $(PLATFORM)/include
SOURCE_RELEASE_SPEC_DIR      = $(SOURCE_RELEASE_MD_DIR)

#
# <user_source_tree> machine-dependent (md) JAR/tar source-side release files
#

MDBINARY_JAR = mdbinary.jar
MDHEADER_JAR = mdheader.jar


# Where to put the results

ifneq ($(RESULTS_DIR),)
	RESULTS_DIR = $(RELEASE_TREE)/sectools/results
endif

