/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* Need to include these first:
#include <jni.h>
#include <seccomon.h>
*/

#ifndef JSS_BIG_INT_H
#define JSS_BIG_INT_H

PR_BEGIN_EXTERN_C

/***********************************************************************
 *
 * J S S _ O c t e t S t r i n g T o B y t e A r r a y
 *
 * Converts a representation of an integer as a big-endian octet string
 * stored in a SECItem (as used by the low-level crypto functions) to a
 * representation of an integer as a big-endian Java byte array. Prepends
 * a zero byte to force it to be positive.
 */
jbyteArray
JSS_OctetStringToByteArray(JNIEnv *env, SECItem *item);

/***********************************************************************
 *
 * J S S _ B y t e A r r a y T o O c t e t S t r i n g
 *
 * Converts an integer represented as a big-endian Java byte array to
 * an integer represented as a big-endian octet string in a SECItem.
 *
 * INPUTS
 *      byteArray
 *          A Java byte array containing an integer represented in
 *          big-endian format.  Must not be NULL.
 *      item
 *          Pointer to a SECItem that will be filled with the integer
 *          from the byte array, in big-endian format.
 * RETURNS
 *      PR_SUCCESS if the operation was successful, PR_FAILURE if an exception
 *      was thrown.
 */
PRStatus
JSS_ByteArrayToOctetString(JNIEnv *env, jbyteArray byteArray, SECItem *item);

PR_END_EXTERN_C

#endif
