/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Netscape Security Services for Java.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1998-2000
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */
#include "_jni/org_mozilla_jss_asn1_ASN1Util.h"
#include <pk11func.h>
#include <nspr.h>
#include <seccomon.h>
#include <key.h>
#include <secitem.h>

#include <jssutil.h>
#include <java_ids.h>
#include <jss_exceptions.h>
#include <Algorithm.h>

/***********************************************************************
 *
 * Java_org_mozilla_jss_asn1_ASN1Util_getTagDescriptionByOid
 *     retrieves OID description by NSS's OID Tag identifier
 *     the OID byte array is expected to be without the OID Tag (6) and size
 *        (together 2 bytes)
 */
JNIEXPORT jstring JNICALL
Java_org_mozilla_jss_asn1_ASN1Util_getTagDescriptionByOid(JNIEnv *env, jobject this, jbyteArray oidBA)
{
    SECItem *oid = NULL;
    SECOidTag oidTag = SEC_OID_UNKNOWN;
    const char *oidDesc = NULL;
    jstring description = (jstring)"";

    if (oidBA == NULL) {
        JSS_throwMsg(env, INVALID_PARAMETER_EXCEPTION,
            "JSS getTagDescriptionByOid: oidBA null");
        goto finish;
    } else {
        /**************************************************
         * Setup the parameters
         *************************************************/
        oid = JSS_ByteArrayToSECItem(env, oidBA);
        if (oid == NULL) {
            JSS_throwMsg(env, INVALID_PARAMETER_EXCEPTION,
                "JSS getTagDescriptionByOid: JSS_ByteArrayToSECItem failed");
            goto finish;
        }

        /*
         * SECOID_FindOIDTag() returns SEC_OID_UNKNOWN if no match
         */
        oidTag = SECOID_FindOIDTag(oid);
        if (oidTag == SEC_OID_UNKNOWN) {
            JSS_throwMsg(env, INVALID_PARAMETER_EXCEPTION,
                "JSS getTagDescriptionByOid: OID UNKNOWN");
            goto finish;
        }

        oidDesc = SECOID_FindOIDTagDescription(oidTag);
        if (oidDesc == NULL) {
            oidDesc = "";
        }
        description = (*env)->NewStringUTF(env, oidDesc);
    }

finish:
    return description;
}
