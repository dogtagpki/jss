/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "_jni/org_mozilla_jss_pkcs11_PK11MessageDigest.h"

#include <nspr.h>
#include <plarena.h>
#include <seccomon.h>
#include <pk11func.h>
#include <secitem.h>

/* JSS includes */
#include <java_ids.h>
#include <jss_exceptions.h>
#include <jssutil.h>
#include <pk11util.h>
#include <Algorithm.h>


/***********************************************************************
 *
 * PK11MessageDigest.initDigest
 *
 */
JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_pkcs11_PK11MessageDigest_initDigest
    (JNIEnv *env, jclass clazz, jobject algObj)
{
    SECOidTag alg;
    PK11Context *context=NULL;

    alg = JSS_getOidTagFromAlg(env, algObj);
    PR_ASSERT( alg != SEC_OID_UNKNOWN ); /* we checked already in Java */

    context = PK11_CreateDigestContext(alg);
    if( context == NULL ) {
        JSS_throwMsg(env, DIGEST_EXCEPTION, "Unable to create digest context");
        return NULL;
    }

    return JSS_PK11_wrapCipherContextProxy(env, &context);
}

/***********************************************************************
 *
 * PK11MessageDigest.initHMAC
 *
 */
JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_pkcs11_PK11MessageDigest_initHMAC
    (JNIEnv *env, jclass clazz, jobject tokenObj, jobject algObj,
     jobject keyObj)
{
    PK11SymKey *origKey = NULL, *newKey=NULL;
    PK11Context *context = NULL;
    CK_MECHANISM_TYPE mech;
    SECItem param;
    jobject contextObj=NULL;

    mech = JSS_getPK11MechFromAlg(env, algObj);
    PR_ASSERT( mech != CKM_INVALID_MECHANISM ); /* we checked already in Java */

    if( JSS_PK11_getSymKeyPtr(env, keyObj, &origKey) != PR_SUCCESS ) {
        /* exception was thrown */
        goto finish;
    }

    /* copy the key, setting the CKA_SIGN attribute */
    /*
    newKey = PK11_CopySymKeyForSigning(origKey, mech);
    if( newKey == NULL ) {
        JSS_throwMsg(env, DIGEST_EXCEPTION,
                        "Unable to set CKA_SIGN attribute on symmetric key");
        goto finish;
    }
    */

    param.data = NULL;
    param.len = 0;

    context = PK11_CreateContextBySymKey(mech, CKA_SIGN, origKey, &param);
    if( context == NULL ) {
        JSS_throwMsg(env, DIGEST_EXCEPTION,
            "Unable to initialize digest context");
        goto finish;
    }

    contextObj = JSS_PK11_wrapCipherContextProxy(env, &context);
finish:
    if(newKey) {
        /* SymKeys are ref counted, and the context will free it's ref
         * when it is destroyed */
        PK11_FreeSymKey(newKey);
    }

    return contextObj;
}


/***********************************************************************
 *
 * PK11MessageDigest.update
 *
 */
JNIEXPORT void JNICALL
Java_org_mozilla_jss_pkcs11_PK11MessageDigest_update
    (JNIEnv *env, jclass clazz, jobject proxyObj, jbyteArray inbufBA,
        jint offset, jint len)
{

    PK11Context *context = NULL;
    jbyte* bytes = NULL;

    if( JSS_PK11_getCipherContext(env, proxyObj, &context) != PR_SUCCESS ) {
        /* exception was thrown */
        goto finish;
    }

    PR_ASSERT( (*env)->GetArrayLength(env, inbufBA) >= offset+len );
    bytes = (*env)->GetByteArrayElements(env, inbufBA, NULL);
    if( bytes == NULL ) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    if( PK11_DigestOp(context, (unsigned char*)(bytes+offset), len)
            != SECSuccess )
    {
        JSS_throwMsg(env, DIGEST_EXCEPTION, "Digest operation failed");
        goto finish;
    }

finish:
    if(bytes) {
        (*env)->ReleaseByteArrayElements(env, inbufBA, bytes, JNI_ABORT);
    }
}


/***********************************************************************
 *
 * PK11MessageDigest.digest
 *
 */
JNIEXPORT jint JNICALL
Java_org_mozilla_jss_pkcs11_PK11MessageDigest_digest
    (JNIEnv *env, jclass clazz, jobject proxyObj, jbyteArray outbuf,
        jint offset, jint len)
{
    PK11Context *context=NULL;
    jbyte *bytes=NULL;
    SECStatus status;
    unsigned int outLen = 0;

    if( JSS_PK11_getCipherContext(env, proxyObj, &context) != PR_SUCCESS) {
        /* exception was thrown */
        goto finish;
    }

    PR_ASSERT( (*env)->GetArrayLength(env, outbuf) >= offset+len );
    bytes = (*env)->GetByteArrayElements(env, outbuf, NULL);
    if( bytes == NULL ) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    status = PK11_DigestFinal(context, (unsigned char*)(bytes+offset),
                    &outLen, len);
    if( status != SECSuccess ) {
        JSS_throwMsg(env, DIGEST_EXCEPTION, "Error occurred while performing"
            " digest operation");
        goto finish;
    }

finish:
    if(bytes) {
        (*env)->ReleaseByteArrayElements(env, outbuf, bytes, 0);
    }
    return outLen;
}
