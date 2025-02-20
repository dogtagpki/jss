/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
#include "_jni/org_mozilla_jss_provider_javax_crypto_JSSTrustManager.h"
#include <jssutil.h>
#include "pk11util.h"
#include "../../../ssl/jssl.h"

/*
 * Class:     org_mozilla_jss_provider_javax_crypto_JSSTrustManager
 * Method:    certRevokeVerify
 * Signature: (Lorg/mozilla/jss/crypto/X509Certificate;)I
 */
JNIEXPORT jint JNICALL Java_org_mozilla_jss_provider_javax_crypto_JSSTrustManager_certRevokeVerify
  (JNIEnv *env, jobject self, jobject Cert, jint usage) {

    CERTCertificate *cert = NULL;
    SECStatus rv = SECFailure;

    if (JSS_PK11_getCertPtr(env, Cert, &cert) != PR_SUCCESS) {
        PR_ASSERT((*env)->ExceptionOccurred(env) != NULL);
        return 0;
    }

    rv = JSSL_verifyCertPKIX( cert, usage,
                     NULL, OCSP_LEAF_AND_CHAIN_POLICY, NULL, NULL);

    if (rv == SECSuccess) return 0;

    return PR_GetError();
    
}