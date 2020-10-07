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
/* The VERSION Strings should be updated everytime a new release    */
/* of JSS is generated. Note that this is done by changing          */
/* cmake/JSSConfig.cmake.                                           */
/********************************************************************/

#define JSS_VERSION  "4.8.0 beta 1"
#define JSS_VMAJOR   4
#define JSS_VMINOR   8
#define JSS_VPATCH   0
#define JSS_BETA     1

#endif
