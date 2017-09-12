/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

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
#include <Algorithm.h>
#include "pk11util.h"
#include <java_ids.h>
#include <jss_exceptions.h>

typedef struct
{
    enum
    {
        PW_NONE = 0,
        PW_FROMFILE = 1,
        PW_PLAINTEXT = 2,
        PW_EXTERNAL = 3
    } source;
    char *data;
} secuPWData;

SECItem *preparePassword(JNIEnv *env, jobject conv, jobject pwObj);

/**********************************************************************
 * PK11Store.putSymKeysInVector
 */
JNIEXPORT void JNICALL
Java_org_mozilla_jss_pkcs11_PK11Store_putSymKeysInVector
    (JNIEnv *env, jobject this, jobject keyVector)
{
    PK11SlotInfo *slot;
    jobject object = NULL;
    jclass vectorClass;
    jmethodID addElement;

    PK11SymKey *firstSymKey= NULL;
    PK11SymKey *sk  = NULL;
    PK11SymKey *nextSymKey = NULL;
    secuPWData  pwdata;

    pwdata.source   = PW_NONE;
    pwdata.data     = (char *) NULL;

    PR_ASSERT(env!=NULL && this!=NULL && keyVector!=NULL);

    if( JSS_PK11_getStoreSlotPtr(env, this, &slot) != PR_SUCCESS) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }
    PR_ASSERT(slot!=NULL);

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

    PK11_Authenticate(slot, PR_TRUE /*load certs*/, NULL /*wincx*/);

    /* Obtain the symmetric key list. */
    firstSymKey = PK11_ListFixedKeysInSlot( slot , NULL, ( void *) &pwdata );
    sk = firstSymKey;

    while(( sk != NULL ))
    {
        if( sk ) {

            nextSymKey = sk;
            object = JSS_PK11_wrapSymKey(env, &sk);

            if(object == NULL) {
                PR_ASSERT( (*env)->ExceptionOccurred(env) );
                goto finish;
            }

            /***************************************************
            * Insert the key into the vector
            ***************************************************/
            (*env)->CallVoidMethod(env, keyVector, addElement, object);
        }

        sk = PK11_GetNextSymKey( nextSymKey );
    }

finish:

    return;
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
     * access to their private keys, so try to log in here.  If we're already
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
    PK11SlotInfo *slotCopy;
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
        slotCopy = PK11_ReferenceSlot(slot);
        object = JSS_PK11_wrapCertAndSlotAndNickname(env,
            &certCopy, &slotCopy, node->appData);
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
 *
 * This function deletes the specified certificate and its associated 
 * private key.
 */
JNIEXPORT void JNICALL
Java_org_mozilla_jss_pkcs11_PK11Store_deleteCert
    (JNIEnv *env, jobject this, jobject certObject)
{
    CERTCertificate *cert;
    SECStatus VARIABLE_MAY_NOT_BE_USED status;

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
    status = SEC_DeletePermCertificate(cert);

finish: 
    return;
}

/**********************************************************************
 * PK11Store.deleteCertOnly
 *
 * This function deletes the specified certificate only.
 */
JNIEXPORT void JNICALL
Java_org_mozilla_jss_pkcs11_PK11Store_deleteCertOnly
    (JNIEnv *env, jobject this, jobject certObject)
{
    CERTCertificate *cert;
    SECStatus VARIABLE_MAY_NOT_BE_USED status;

    PR_ASSERT(env!=NULL && this!=NULL);
    if(certObject == NULL) {
        JSS_throw(env, NO_SUCH_ITEM_ON_TOKEN_EXCEPTION);
        goto finish;
    }

    if( JSS_PK11_getCertPtr(env, certObject, &cert) != PR_SUCCESS) {
        PR_ASSERT( (*env)->ExceptionOccurred(env) != NULL);
        goto finish;
    }

    status = SEC_DeletePermCertificate(cert);

finish: 
    return;
}

#define DER_DEFAULT_CHUNKSIZE (2048)

int PK11_NumberObjectsFor(PK11SlotInfo*, CK_ATTRIBUTE*, int);

/***********************************************************************
 * PK11Store.importdPrivateKey
 */
JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_pkcs11_PK11Store_importPrivateKey
    (   JNIEnv *env,
        jobject this,
        jbyteArray keyArray,
        jobject keyTypeObj,
        jboolean temporary            )
{
    SECItem derPK;
    PK11SlotInfo *slot;
    jthrowable excep;
    SECStatus status;
    SECItem nickname;
    jobject privkObj = NULL;

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

    SECKEYPrivateKey *privk = NULL;
    status = PK11_ImportDERPrivateKeyInfoAndReturnKey(
                slot, &derPK, &nickname,
                NULL /*public value*/, !temporary /*isPerm*/,
                PR_TRUE /*isPrivate*/, 0 /*keyUsage*/,
                &privk, NULL /*wincx*/);
    if(status != SECSuccess) {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "Failed to import private key info");
        goto finish;
    }

    privkObj = JSS_PK11_wrapPrivKey(env, &privk);
    if (privkObj == NULL) {
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
    return privkObj;
}

extern const SEC_ASN1Template SECKEY_EncryptedPrivateKeyInfoTemplate[];


JNIEXPORT jbyteArray JNICALL
Java_org_mozilla_jss_pkcs11_PK11Store_getEncryptedPrivateKeyInfo(
    JNIEnv *env,
    jobject this,
    jobject conv,
    jobject pwObj,
    jobject algObj,
    jint iterations,
    jobject key)
{
    // initialisations so we can goto finish
    SECItem *pwItem = NULL;
    SECKEYEncryptedPrivateKeyInfo *epki = NULL;
    SECItem epkiItem;
    epkiItem.data = NULL;
    epkiItem.len = 0;

    PR_ASSERT(env != NULL && this != NULL);

    if (pwObj == NULL || algObj == NULL || key == NULL) {
        JSS_throw(env, NULL_POINTER_EXCEPTION);
        goto finish;
    }

    if (iterations <= 0) {
        iterations = 2000;  // set default iterations
    }

    // get slot
    PK11SlotInfo *slot = NULL;
    if( JSS_PK11_getStoreSlotPtr(env, this, &slot) != PR_SUCCESS) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }
    PR_ASSERT(slot!=NULL);

    // get algorithm
    SECOidTag algTag = JSS_getOidTagFromAlg(env, algObj);
    if (algTag == SEC_OID_UNKNOWN) {
        JSS_throwMsg(env, NO_SUCH_ALG_EXCEPTION, "Unrecognized algorithm");
        goto finish;
    }

    pwItem = preparePassword(env, conv, pwObj);
    if (pwItem == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    // get key
    SECKEYPrivateKey *privk;
    if (JSS_PK11_getPrivKeyPtr(env, key, &privk) != PR_SUCCESS) {
        PR_ASSERT( (*env)->ExceptionOccurred(env) != NULL);
        goto finish;
    }

    // export the epki
    epki = PK11_ExportEncryptedPrivKeyInfo(
        slot, algTag, pwItem, privk, iterations, NULL /*wincx*/);
    if (epki == NULL) {
        JSS_throwMsgPrErr(
            env, TOKEN_EXCEPTION, "Failed to export EncryptedPrivateKeyInfo");
        goto finish;
    }

    // DER-encode the epki
    if (SEC_ASN1EncodeItem(NULL, &epkiItem, epki,
        SEC_ASN1_GET(SECKEY_EncryptedPrivateKeyInfoTemplate)) == NULL) {
        JSS_throwMsg(
            env, TOKEN_EXCEPTION,
            "Failed to ASN1-encode EncryptedPrivateKeyInfo");
        goto finish;
    }

    // convert to Java byte array
    jbyteArray encodedEpki = JSS_SECItemToByteArray(env, &epkiItem);

finish:
    if (epki != NULL) {
        SECKEY_DestroyEncryptedPrivateKeyInfo(epki, PR_TRUE /*freeit*/);
    }
    if (epkiItem.data != NULL) {
        SECITEM_FreeItem(&epkiItem, PR_FALSE /*freeit*/);
    }
    if (pwItem != NULL) {
        SECITEM_FreeItem(pwItem, PR_TRUE /*freeit*/);
    }
    return encodedEpki;
}


JNIEXPORT void JNICALL
Java_org_mozilla_jss_pkcs11_PK11Store_importEncryptedPrivateKeyInfo(
    JNIEnv *env,
    jobject this,
    jobject conv,
    jobject pwObj,
    jstring nickname,
    jobject pubKeyObj,
    jbyteArray epkiBytes)
{
    // initialisations so we can goto finish
    SECItem *epkiItem = NULL;
    SECKEYEncryptedPrivateKeyInfo *epki = NULL;
    SECItem *pwItem = NULL;
    SECItem *spkiItem = NULL;
    CERTSubjectPublicKeyInfo *spki = NULL;
    SECKEYPublicKey *pubKey = NULL;
    const char *nicknameChars = NULL;

    PR_ASSERT(env != NULL && this != NULL);

    if (pwObj == NULL || nickname == NULL || pubKeyObj == NULL) {
        JSS_throw(env, NULL_POINTER_EXCEPTION);
        goto finish;
    }

    // get slot
    PK11SlotInfo *slot = NULL;
    if (JSS_PK11_getStoreSlotPtr(env, this, &slot) != PR_SUCCESS) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }
    PR_ASSERT(slot != NULL);

    // decode EncryptedPrivateKeyInfo
    epkiItem = JSS_ByteArrayToSECItem(env, epkiBytes);
    epki = PR_Calloc(1, sizeof(SECKEYEncryptedPrivateKeyInfo));
    if (SEC_ASN1DecodeItem(
                NULL,
                epki,
                SEC_ASN1_GET(SECKEY_EncryptedPrivateKeyInfoTemplate),
                epkiItem
            ) != SECSuccess) {
        JSS_throwMsg(env, INVALID_DER_EXCEPTION,
            "Failed to decode EncryptedPrivateKeyInfo");
        goto finish;
    }

    pwItem = preparePassword(env, conv, pwObj);
    if (pwItem == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    // get public key value
    jclass pubKeyClass = (*env)->GetObjectClass(env, pubKeyObj);
    if (pubKeyClass == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }
    jmethodID getEncoded = (*env)->GetMethodID(
        env, pubKeyClass, "getEncoded", "()[B");
    if (getEncoded == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }
    jbyteArray spkiBytes = (*env)->CallObjectMethod(
        env, pubKeyObj, getEncoded);
    spkiItem = JSS_ByteArrayToSECItem(env, spkiBytes);
    spki = PR_Calloc(1, sizeof(CERTSubjectPublicKeyInfo));
    if (SEC_ASN1DecodeItem(
                NULL,
                spki,
                SEC_ASN1_GET(CERT_SubjectPublicKeyInfoTemplate),
                spkiItem
            ) != SECSuccess) {
        JSS_throwMsg(env, INVALID_DER_EXCEPTION,
            "Failed to decode SubjectPublicKeyInfo");
        goto finish;
    }

    pubKey = SECKEY_ExtractPublicKey(spki);
    if (pubKey == NULL) {
        JSS_throwMsgPrErr(env, INVALID_DER_EXCEPTION,
            "Failed to extract public key from SubjectPublicKeyInfo");
        goto finish;
    }

    SECItem *pubValue;
    switch (pubKey->keyType) {
        case dsaKey:
            pubValue = &pubKey->u.dsa.publicValue;
            break;
        case dhKey:
            pubValue = &pubKey->u.dh.publicValue;
            break;
        case rsaKey:
            pubValue = &pubKey->u.rsa.modulus;
            break;
        case ecKey:
            pubValue = &pubKey->u.ec.publicValue;
            break;
        default:
            pubValue = NULL;
    }

    // prepare nickname
    nicknameChars = (*env)->GetStringUTFChars(env, nickname, NULL);
    if (nicknameChars == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }
    SECItem nickItem;
    nickItem.data = nicknameChars;
    nickItem.len = (*env)->GetStringUTFLength(env, nickname);

    // if keyUsage = 0, defaults to signing and encryption/key agreement.
    //   see pk11akey.c in NSS
    int keyUsage = 0;

    // perform import
    SECStatus result = PK11_ImportEncryptedPrivateKeyInfo(
        slot, epki, pwItem, &nickItem, pubValue,
        PR_TRUE /* isperm */, PR_TRUE /* isprivate */,
        pubKey->keyType, keyUsage, NULL /* wincx */);
    if (result != SECSuccess) {
        JSS_throwMsgPrErr(
            env, TOKEN_EXCEPTION,
            "Failed to import EncryptedPrivateKeyInfo to token");
        goto finish;
    }

finish:
    if (epkiItem != NULL) {
        SECITEM_FreeItem(epkiItem, PR_TRUE /*freeit*/);
    }
    if (epki != NULL) {
        SECKEY_DestroyEncryptedPrivateKeyInfo(epki, PR_TRUE /*freeit*/);
    }
    if (spkiItem != NULL) {
        SECITEM_FreeItem(spkiItem, PR_TRUE /*freeit*/);
    }
    if (spki != NULL) {
        SECKEY_DestroySubjectPublicKeyInfo(spki);
    }
    if (pwItem != NULL) {
        SECITEM_FreeItem(pwItem, PR_TRUE /*freeit*/);
    }
    if (pubKey != NULL) {
        SECKEY_DestroyPublicKey(pubKey);
    }
    if (nicknameChars != NULL) {
        (*env)->ReleaseStringUTFChars(env, nickname, nicknameChars);
    }
}

/* Process the given password through the given PasswordConverter,
 * returning a new SECItem* on success.
 *
 * After use, the caller should free the SECItem:
 *
 *   SECITEM_FreeItem(pwItem, PR_TRUE).
 */
SECItem *preparePassword(JNIEnv *env, jobject conv, jobject pwObj) {
    jclass passwordClass = (*env)->GetObjectClass(env, pwObj);
    if (passwordClass == NULL) {
        ASSERT_OUTOFMEM(env);
        return NULL;
    }

    jbyteArray pwBytes;

    if (conv == NULL) {
        jmethodID getByteCopy = (*env)->GetMethodID(
            env, passwordClass, PW_GET_BYTE_COPY_NAME, PW_GET_BYTE_COPY_SIG);
        if (getByteCopy == NULL) {
            ASSERT_OUTOFMEM(env);
            return NULL;
        }
        pwBytes = (*env)->CallObjectMethod(env, pwObj, getByteCopy);
    } else {
        jmethodID getChars = (*env)->GetMethodID(
            env, passwordClass, "getChars", "()[C");
        if (getChars == NULL) {
            ASSERT_OUTOFMEM(env);
            return NULL;
        }
        jcharArray pwChars = (*env)->CallObjectMethod(env, pwObj, getChars);

        jclass convClass = (*env)->GetObjectClass(env, conv);
        if (conv == NULL) {
            ASSERT_OUTOFMEM(env);
            return NULL;
        }
        jmethodID convert = (*env)->GetMethodID(
            env, convClass, "convert", "([C)[B");
        if (convert == NULL) {
            ASSERT_OUTOFMEM(env);
            return NULL;
        }
        pwBytes = (*env)->CallObjectMethod(env, conv, convert, pwChars);
    }

    return JSS_ByteArrayToSECItem(env, pwBytes);
}
