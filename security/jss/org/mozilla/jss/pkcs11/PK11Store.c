/* 
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 * 
 * The Original Code is the Netscape Security Services for Java.
 * 
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation.  Portions created by Netscape are 
 * Copyright (C) 1998-2000 Netscape Communications Corporation.  All
 * Rights Reserved.
 * 
 * Contributor(s):
 * 
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable 
 * instead of those above.  If you wish to allow use of your 
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the
 * GPL.
 */

#include "_jni/org_mozilla_jss_pkcs11_PK11Store.h"

#include <plarena.h>
#include <nspr.h>
#include <key.h>
#include <secmod.h>
#include <pk11func.h>
#include <cert.h>
#include <certdb.h>
#include <secasn1.h>

#include <jssutil.h>
#include "pk11util.h"
#include <java_ids.h>
#include <jss_exceptions.h>

/***********************************************************************
 * HACKS which belong in pk11cert.c
 ***********************************************************************/
typedef struct pk11KeyCallbackStr {
        SECStatus (* callback)(SECKEYPrivateKey *,void *);
        void *callbackArg;
        void *wincx;
} pk11KeyCallback;

/**********************************************************************
 * Callback information for keyTraversalCallback
 */
typedef enum {
    CERT_OBJECT,
    KEY_OBJECT
} ObjectType;
typedef struct {
    JNIEnv *env;
    jobject vector;
    ObjectType type;
} TraversalCallbackInfo;

/**********************************************************************
 * traversalCallback
 *
 * Generic callback that does the job for both private keys
 * and certificates.
 *
 */
static SECStatus
traversalCallback(void *keyCert, void *arg)
{
    TraversalCallbackInfo *info;
    jclass vectorClass;
    jmethodID addElement;
    jobject object=NULL;
    jobject vector;
    JNIEnv *env;
    SECKEYPrivateKey *key=NULL;
    SECKEYPrivateKey *keyCopy=NULL;
    CERTCertificate *cert=NULL;
    CERTCertificate *certCopy=NULL;
    SECStatus status = SECFailure;

    /**************************************************
     * Get the callback data
     **************************************************/
    if(arg == NULL) {
        JSS_trace(env, JSS_TRACE_ERROR,
            "traversalCallback called with NULL argument");
        PR_ASSERT(PR_FALSE);
        goto finish;
    }
    info = (TraversalCallbackInfo*)arg;
    env = info->env;
    vector = info->vector;
    if(info->type == KEY_OBJECT) {
        key = (SECKEYPrivateKey*)keyCert;
    } else {
        PR_ASSERT(info->type == CERT_OBJECT);
        cert = (CERTCertificate*)keyCert;
    }
    if(env==NULL || vector==NULL) {
        PR_ASSERT(PR_FALSE);
        goto finish;
    }

    /**************************************************
     * Get JNI ids
     **************************************************/
    vectorClass = (*env)->GetObjectClass(env, vector);
    if(vectorClass == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }
    addElement = (*env)->GetMethodID(env,
                                     vectorClass,
                                     VECTOR_ADD_ELEMENT_NAME,
                                     VECTOR_ADD_ELEMENT_SIG);
    if(addElement == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    /***************************************************
     * Wrap the object
     ***************************************************/
    if(info->type == KEY_OBJECT) {

      /** Private keys may be temporary now...
        if(key->pkcs11IsTemp) {
            JSS_trace(env, JSS_TRACE_ERROR,
                "Private Key passed to keyTraversalCallback is a"
                " temporary object");
            PR_ASSERT(PR_FALSE);
            goto finish;
        }
      */

        keyCopy = SECKEY_CopyPrivateKey(key);
        object = JSS_PK11_wrapPrivKey(env, &keyCopy);
    } else {
        PR_ASSERT( info->type == CERT_OBJECT );

        certCopy = CERT_DupCertificate(cert);
        object = JSS_PK11_wrapCert(env, &certCopy);
    }
    if(object == NULL) {
        PR_ASSERT( (*env)->ExceptionOccurred(env) );
        goto finish;
    }
        

    /***************************************************
     * Insert the key into the vector
     ***************************************************/
    (*env)->CallVoidMethod(env, vector, addElement, object);

    status = SECSuccess;

finish:
    if(object==NULL) {
        if(keyCopy!=NULL) {
            SECKEY_DestroyPrivateKey(keyCopy);
        }
        if(certCopy!=NULL) {
            CERT_DestroyCertificate(certCopy);
        }
    }
    return status;
}

/**********************************************************************
 * certTraversalCallback
 *
 * Given a certificate and vector, inserts the certificate into the vector.
 *
 */
static SECStatus
certTraversalCallback(CERTCertificate *cert, void *arg)
{
    PR_ASSERT( ((TraversalCallbackInfo*)arg)->type == CERT_OBJECT);
    return traversalCallback( (void*)cert, arg);
}


/**********************************************************************
 * PK11Store.putKeysInVector
 */
JNIEXPORT void JNICALL
Java_org_mozilla_jss_pkcs11_PK11Store_putKeysInVector
    (JNIEnv *env, jobject this, jobject keyVector)
{
    PK11SlotInfo *slot;
    SECKEYPrivateKeyList *keyList = NULL;
    SECKEYPrivateKey* keyCopy = NULL;
    jobject object = NULL;
    jclass vectorClass;
    jmethodID addElement;
    SECKEYPrivateKeyListNode *node = NULL;

    PR_ASSERT(env!=NULL && this!=NULL && keyVector!=NULL);

    if( JSS_PK11_getStoreSlotPtr(env, this, &slot) != PR_SUCCESS) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }
    PR_ASSERT(slot!=NULL);

    /*
     * Most, if not all, tokens have to be logged in before they allow
     * access to their private keys, so try to login here.  If we're already
     * logged in, this is a no-op.
     * If the login fails, go ahead and try to get the keys anyway, in case
     * this is an exceptionally promiscuous token.
     */
    PK11_Authenticate(slot, PR_TRUE /*load certs*/, NULL /*wincx*/);

    /*
     * Get the list of keys on this token
     */
    keyList = PK11_ListPrivateKeysInSlot(slot);
    if( keyList == NULL ) {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "PK11_ListPrivateKeysInSlot "
            "returned an error");
        goto finish;
    }

    /**************************************************
     * Get JNI ids
     **************************************************/
    vectorClass = (*env)->GetObjectClass(env, keyVector);
    if(vectorClass == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }
    addElement = (*env)->GetMethodID(env,
                                     vectorClass,
                                     VECTOR_ADD_ELEMENT_NAME,
                                     VECTOR_ADD_ELEMENT_SIG);
    if(addElement == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    for(    node = PRIVKEY_LIST_HEAD(keyList);
            !PRIVKEY_LIST_END(node, keyList);
            node = PRIVKEY_LIST_NEXT(node) )
    {
        /***************************************************
        * Wrap the object
        ***************************************************/
        keyCopy = SECKEY_CopyPrivateKey(node->key);
        object = JSS_PK11_wrapPrivKey(env, &keyCopy);
        if(object == NULL) {
            PR_ASSERT( (*env)->ExceptionOccurred(env) );
            goto finish;
        }

        /***************************************************
        * Insert the key into the vector
        ***************************************************/
        (*env)->CallVoidMethod(env, keyVector, addElement, object);
    }

finish:
    if( keyList != NULL ) {
        SECKEY_DestroyPrivateKeyList(keyList);
    }
    return;
}

/**********************************************************************
 * PK11Store.putCertsInVector
 */
JNIEXPORT void JNICALL
Java_org_mozilla_jss_pkcs11_PK11Store_putCertsInVector
    (JNIEnv *env, jobject this, jobject certVector)
{
    PK11SlotInfo *slot;
    jclass vectorClass;
    jmethodID addElement;
    CERTCertList *certList = NULL;
    CERTCertificate *certCopy;
    CERTCertListNode *node = NULL;
    jobject object;

    PR_ASSERT(env!=NULL && this!=NULL && certVector!=NULL);

    if( JSS_PK11_getStoreSlotPtr(env, this, &slot) != PR_SUCCESS) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }
    PR_ASSERT(slot!=NULL);

    /*
     * log in if the slot does not have publicly readable certs
     */
    if( !PK11_IsFriendly(slot) ) {
        PK11_Authenticate(slot, PR_TRUE /*load certs*/, NULL /*wincx*/);
    }

    certList = PK11_ListCertsInSlot(slot);
    if( certList == NULL ) {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "PK11_ListCertsInSlot "
            "returned an error");
        goto finish;
    }

    /**************************************************
     * Get JNI ids
     **************************************************/
    vectorClass = (*env)->GetObjectClass(env, certVector);
    if(vectorClass == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }
    addElement = (*env)->GetMethodID(env,
                                     vectorClass,
                                     VECTOR_ADD_ELEMENT_NAME,
                                     VECTOR_ADD_ELEMENT_SIG);
    if(addElement == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    for(    node = CERT_LIST_HEAD(certList);
            !CERT_LIST_END(node, certList);
            node = CERT_LIST_NEXT(node) )
    {
        /***************************************************
        * Wrap the object
        ***************************************************/
        certCopy = CERT_DupCertificate(node->cert);
        object = JSS_PK11_wrapCert(env, &certCopy);
        if(object == NULL) {
            PR_ASSERT( (*env)->ExceptionOccurred(env) );
            goto finish;
        }

        /***************************************************
        * Insert the cert into the vector
        ***************************************************/
        (*env)->CallVoidMethod(env, certVector, addElement, object);
    }

finish:
    if( certList != NULL ) {
        CERT_DestroyCertList(certList);
    }
    return;
}

/************************************************************************
 *
 * J S S _ g e t S t o r e S l o t P t r
 *
 * Retrieve the PK11SlotInfo pointer of the given PK11Store.
 *
 * INPUTS
 *      store
 *          A reference to a Java PK11Store
 *      slot
 *          address of a PK11SlotInfo* that will be loaded with
 *          the PK11SlotInfo pointer of the given token.
 * RETURNS
 *      PR_SUCCESS if the operation was successful, PR_FAILURE if an
 *      exception was thrown.
 */
PRStatus
JSS_PK11_getStoreSlotPtr(JNIEnv *env, jobject store, PK11SlotInfo **slot)
{
    PR_ASSERT(env!=NULL && store!=NULL && slot!=NULL);

    return JSS_getPtrFromProxyOwner(env, store, PK11STORE_PROXY_FIELD,
                PK11STORE_PROXY_SIG, (void**)slot);
}

/**********************************************************************
 * PK11Store.deletePrivateKey
 */
JNIEXPORT void JNICALL
Java_org_mozilla_jss_pkcs11_PK11Store_deletePrivateKey
    (JNIEnv *env, jobject this, jobject key)
{
    PK11SlotInfo *slot;
    SECKEYPrivateKey *privk;

    PR_ASSERT(env!=NULL && this!=NULL);
    if(key == NULL) {
        JSS_throw(env, NO_SUCH_ITEM_ON_TOKEN_EXCEPTION);
        goto finish;
    }

    /**************************************************
     * Get the C structures
     **************************************************/
    if( JSS_PK11_getStoreSlotPtr(env, this, &slot) != PR_SUCCESS) {
        PR_ASSERT( (*env)->ExceptionOccurred(env) != NULL);
        goto finish;
    }

    if( JSS_PK11_getPrivKeyPtr(env, key, &privk) != PR_SUCCESS) {
        PR_ASSERT( (*env)->ExceptionOccurred(env) != NULL);
        goto finish;
    }

    /***************************************************
     * Validate structures
     ***************************************************/

    /* A private key may be temporary, but you can't use this function
     * to delete it.  Instead, just let it be garbage collected */
    if( privk->pkcs11IsTemp ) {
        PR_ASSERT(PR_FALSE);
        JSS_throwMsg(env, TOKEN_EXCEPTION,
            "Private Key is not a permanent PKCS #11 object");
        goto finish;
    }

    if( slot != privk->pkcs11Slot) {
        JSS_throw(env, NO_SUCH_ITEM_ON_TOKEN_EXCEPTION);
        goto finish;
    }

    /***************************************************
     * Perform the destruction
     ***************************************************/
    if( PK11_DestroyTokenObject(privk->pkcs11Slot, privk->pkcs11ID)
        != SECSuccess)
    {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "Unable to actually destroy object");
        goto finish;
    }

finish:
    return;
}

/**********************************************************************
 * PK11Store.deleteCert
 */
JNIEXPORT void JNICALL
Java_org_mozilla_jss_pkcs11_PK11Store_deleteCert
    (JNIEnv *env, jobject this, jobject certObject)
{
    CERTCertificate *cert;
    SECStatus status;

    PR_ASSERT(env!=NULL && this!=NULL);
    if(certObject == NULL) {
        JSS_throw(env, NO_SUCH_ITEM_ON_TOKEN_EXCEPTION);
        goto finish;
    }

    if( JSS_PK11_getCertPtr(env, certObject, &cert) != PR_SUCCESS) {
        PR_ASSERT( (*env)->ExceptionOccurred(env) != NULL);
        goto finish;
    }

    status = PK11_DeleteTokenCertAndKey(cert, NULL);

finish: 
    return;
}

#define DER_DEFAULT_CHUNKSIZE (2048)

/***********************************************************************
 * passwordToSecitem
 * 
 * Converts a Java Password object to a SECItem, first hashing with
 * global salt. The Java Password object will be cleared.
 * Returns NULL iff an exception was thrown.
 */
static SECItem*
passwordToSecitem(JNIEnv *env, jobject pwObject, jbyteArray globalSaltArray)
{
    jclass passwordClass;
    jmethodID getByteCopyMethod;
    jmethodID clearMethod;
    jbyteArray pwArray;
    SECItem *ret=NULL;
    jbyte *pwChars;
    jthrowable excep;
    SECItem *salt = NULL;

    PR_ASSERT(env!=NULL && pwObject!=NULL);

    ret = (SECItem*) PR_NEW(SECItem);
    if(ret == NULL) {
        JSS_throw(env, OUT_OF_MEMORY_ERROR);
        goto finish;
    }

    /*****************************************
     * Get Password class and methods
     *****************************************/
    passwordClass = (*env)->GetObjectClass(env, pwObject);
    if(passwordClass == NULL) {
        goto finish;
    }
    getByteCopyMethod = (*env)->GetMethodID(
                                            env,
                                            passwordClass,
                                            PW_GET_BYTE_COPY_NAME,
                                            PW_GET_BYTE_COPY_SIG);
    clearMethod = (*env)->GetMethodID(  env,
                                        passwordClass,
                                        PW_CLEAR_NAME,
                                        PW_CLEAR_SIG);
    if(getByteCopyMethod==NULL || clearMethod==NULL) {
        goto finish;
    }

    /***************************************************
     * Get the salt
     ***************************************************/
    salt = PR_NEW(SECItem);
    if( salt == NULL ) {
        JSS_throw(env, OUT_OF_MEMORY_ERROR);
        goto finish;
    }
    salt->len = (*env)->GetArrayLength(env, globalSaltArray);
    PR_ASSERT(salt->len > 0);
    salt->data = (unsigned char*)
                    (*env)->GetByteArrayElements(env, globalSaltArray, NULL);
    if( salt->data == NULL ) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    /************************************************
     * Get the bytes from the password, then clear it
     ***********************************************/
    pwArray = (*env)->CallObjectMethod( env, pwObject, getByteCopyMethod);
    (*env)->CallVoidMethod(env, pwObject, clearMethod);
    if(pwArray == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    /*************************************************************
     * Copy the characters out of the byte array,
     *************************************************************/
    pwChars = (*env)->GetByteArrayElements(env, pwArray, NULL);
    if(pwChars == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }
    /* hash the password into a SECItem */
    ret = SECKEY_HashPassword( (char*) pwChars, salt);

    /***************************************************
     * Clear the array.
     ***************************************************/
    memset(pwChars, 0, ret->len);
    (*env)->ReleaseByteArrayElements(env, pwArray, pwChars, 0);

finish:
    if( (excep=(*env)->ExceptionOccurred(env)) ) {
        (*env)->ExceptionClear(env);
    }
    if(salt) {
        if(salt->data) {
            (*env)->ReleaseByteArrayElements(env, globalSaltArray,
                                             (jbyte*) salt->data, JNI_ABORT);
        }
        PR_Free(salt);
    }
    if( excep ) {
        (*env)->Throw(env, excep);
    }
    return ret;
}

int PK11_NumberObjectsFor(PK11SlotInfo*, CK_ATTRIBUTE*, int);

/***********************************************************************
 * importPrivateKey
 */
static void
importPrivateKey
    (   JNIEnv *env,
        jobject this,
        jbyteArray keyArray,
        jobject keyTypeObj,
        PRBool temporary            )
{
    SECItem derPK;
    PK11SlotInfo *slot;
    jthrowable excep;
    KeyType keyType;
    SECStatus status;
    SECItem nickname;

    keyType = JSS_PK11_getKeyType(env, keyTypeObj);
    if( keyType == nullKey ) {
        /* exception was thrown */
        goto finish;
    }

    /*
     * initialize so we can goto finish
     */
    derPK.data = NULL;
    derPK.len = 0;


    PR_ASSERT(env!=NULL && this!=NULL);

    if(keyArray == NULL) {
        JSS_throw(env, NULL_POINTER_EXCEPTION);
        goto finish;
    }

    /*
     * copy the java byte array into a local copy
     */
    derPK.len = (*env)->GetArrayLength(env, keyArray);
    if(derPK.len <= 0) {
        JSS_throwMsg(env, INVALID_KEY_FORMAT_EXCEPTION, "Key array is empty");
        goto finish;
    }
    derPK.data = (unsigned char*)
            (*env)->GetByteArrayElements(env, keyArray, NULL);
    if(derPK.data == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    /*
     * Get the PKCS #11 slot
     */
    if( JSS_PK11_getStoreSlotPtr(env, this, &slot) != PR_SUCCESS) {
        PR_ASSERT( (*env)->ExceptionOccurred(env) != NULL);
        goto finish;
    }

    nickname.len = 0;
    nickname.data = NULL;

    status = PK11_ImportDERPrivateKeyInfo(slot, &derPK, &nickname,
                NULL /*public value*/, PR_TRUE /*isPerm*/,
                PR_TRUE /*isPrivate*/, 0 /*keyUsage*/, NULL /*wincx*/);
    if(status != SECSuccess) {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "Failed to import private key info");
        goto finish;
    }

finish:
    /* Save any exceptions */
    if( (excep=(*env)->ExceptionOccurred(env)) ) {
        (*env)->ExceptionClear(env);
    }
    if(derPK.data != NULL) {
        (*env)->ReleaseByteArrayElements(   env,
                                            keyArray,
                                            (jbyte*) derPK.data,
                                            JNI_ABORT           );
    }
    /* now re-throw the exception */
    if( excep ) {
        (*env)->Throw(env, excep);
    }
}


/***********************************************************************
 * PK11Store.importdPrivateKey
 */
JNIEXPORT void JNICALL
Java_org_mozilla_jss_pkcs11_PK11Store_importPrivateKey
    (   JNIEnv *env,
        jobject this,
        jbyteArray keyArray,
        jobject keyTypeObj        )
{
    importPrivateKey(env, this, keyArray,
        keyTypeObj, PR_FALSE /* not temporary */);
}
