/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef JSSVER_H
#define JSSVER_H

/*
 * JSS's major version, minor version, patch level, and whether
 * this is a beta release.
 *
 * The format of the version string should be
 *     "<major version>.<minor version>[.<patch level>] [<Beta>]"
 */

/********************************************************************/
/* The VERSION Strings should be updated in the following           */
/* files everytime a new release of JSS is generated:               */
/*                                                                  */
/* org/mozilla/jss/CryptoManager.java                               */
/* org/mozilla/jss/CryptoManager.c                                  */
/* org/mozilla/jss/JSSProvider.java                                 */
/* org/mozilla/jss/util/jssver.h                                    */
/* lib/manifest.mn                                                  */
/*                                                                  */
/********************************************************************/

#define JSS_VERSION  "4.3.2"
#define JSS_VMAJOR   4
#define JSS_VMINOR   3
#define JSS_VPATCH   2
#define JSS_BETA     PR_FALSE

#endif
