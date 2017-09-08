/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "_jni/org_mozilla_jss_pkcs11_SymKeyProxy.h"

#include <nspr.h>
#include <plarena.h>
#include <secmodt.h>
#include <pk11func.h>

#include <jss_exceptions.h>
#include <java_ids.h>
#include <jssutil.h>
#include "pk11util.h"

/***********************************************************************
 *
 * J S S _ P K 1 1 _ w r a p S y m K e y

 * Puts a Symmetric Key into a Java object.
 * (Does NOT perform a cryptographic "wrap" operation.)
 * symKey: will be stored in a Java wrapper.
 * Returns: a new PK11SymKey, or NULL if an exception occurred.
 */
jobject
JSS_PK11_wrapSymKey(JNIEnv *env, PK11SymKey **symKey)
{
    jclass keyClass;
    jmethodID constructor;
    jbyteArray ptrArray;
    jobject Key=NULL;
    char *nickname = NULL;
    jstring jnickname = NULL;

    PR_ASSERT(env!=NULL && symKey!=NULL && *symKey!=NULL);

    /* find the class */
    keyClass = (*env)->FindClass(env, PK11SYMKEY_CLASS_NAME);
    if( keyClass == NULL ) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    nickname = PK11_GetSymKeyNickname( *symKey );

    if (nickname) {
        jnickname = (*env)->NewStringUTF(env, nickname);
    }

    /* find the constructor */
    constructor = (*env)->GetMethodID(env, keyClass,
                                        PLAIN_CONSTRUCTOR,
                                        PK11SYMKEY_CONSTRUCTOR_1_SIG);
    if(constructor == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    /* convert the pointer to a byte array */
    ptrArray = JSS_ptrToByteArray(env, (void*)*symKey);
    if( ptrArray == NULL ) {
        goto finish;
    }
    /* call the constructor */
    Key = (*env)->NewObject(env, keyClass, constructor, ptrArray, jnickname);

finish:
    if(Key == NULL) {
        PK11_FreeSymKey(*symKey);
    }
    if(nickname != NULL) {
        PORT_Free(nickname);
        nickname = NULL;
    }
    *symKey = NULL;
    return Key;
}

/***********************************************************************
 *
 * PK11SymKey.getOwningToken
 */
JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_pkcs11_PK11SymKey_getOwningToken
    (JNIEnv *env, jobject this)
{
    PK11SymKey *key = NULL;
    PK11SlotInfo *slot = NULL;
    jobject token = NULL;

    PR_ASSERT(env!=NULL && this!=NULL);

    /* Get the C key structure */
    if( JSS_PK11_getSymKeyPtr(env, this, &key) != PR_SUCCESS) {
        PR_ASSERT( (*env)->ExceptionOccurred(env) != NULL);
        goto finish;
    }

    /* Get the slot this key lives on */
    slot = PK11_GetSlotFromKey(key);
    PR_ASSERT(slot != NULL);

    /* Turn the slot into a Java PK11Token */
    token = JSS_PK11_wrapPK11Token(env, &slot);
    if(token == NULL) {
        PR_ASSERT( (*env)->ExceptionOccurred(env) );
        goto finish;
    }

finish:
    if(slot != NULL) {
        PK11_FreeSlot(slot);
    }
    return token;
}

/***********************************************************************
 *
 * PK11SymKey.getStrength
 */
JNIEXPORT jint JNICALL
Java_org_mozilla_jss_pkcs11_PK11SymKey_getStrength
    (JNIEnv *env, jobject this)
{
    PK11SymKey *key=NULL;
    int strength = 0;

    /* get the key pointer */
    if( JSS_PK11_getSymKeyPtr(env, this, &key) != PR_SUCCESS) {
        goto finish;
    }

    strength = PK11_GetKeyStrength(key, NULL /*algid*/);

finish:
    return strength;
}

/***********************************************************************
 *
 * PK11SymKey.getLength
 */
JNIEXPORT jint JNICALL
Java_org_mozilla_jss_pkcs11_PK11SymKey_getLength
    (JNIEnv *env, jobject this)
{
    PK11SymKey *key=NULL;
    unsigned int strength = 0;

    /* get the key pointer */
    if( JSS_PK11_getSymKeyPtr(env, this, &key) != PR_SUCCESS) {
        goto finish;
    }

    strength = PK11_GetKeyLength(key);

finish:
    return (jint) strength;
}

/***********************************************************************
 *
 * PK11SymKey.setNickNameNative
 */
JNIEXPORT void JNICALL
Java_org_mozilla_jss_pkcs11_PK11SymKey_setNickNameNative
    (JNIEnv *env, jobject this,jstring nickname)
{
    PK11SymKey *key=NULL;
    const char *keyname = NULL;
    SECStatus status;

    /* If no nickname provided, we are done */
    if( nickname == NULL ) {
        JSS_throwMsgPrErr(env, TOKEN_EXCEPTION,
            "Nickname is NULL, will not be set");
        goto finish;
    }

    /* get the key pointer */
    if( JSS_PK11_getSymKeyPtr(env, this, &key) != PR_SUCCESS) {
        goto finish;
    }

    /* convert the Java String into a native "C" string */
    keyname = (*env)->GetStringUTFChars( env, nickname, 0 );

    /* name the key */
    status = PK11_SetSymKeyNickname( key, keyname );
    if( status != SECSuccess ) {
        JSS_throwMsgPrErr(env, TOKEN_EXCEPTION,
            "Failed to name symmetric key");
    }
finish:

    if( keyname != NULL ) {
        /* free the native "C" string */
        (*env)->ReleaseStringUTFChars(env, nickname, keyname);
    }

    return;
}

/***********************************************************************
 *
 * PK11SymKey.getKeyData
 */
JNIEXPORT jbyteArray JNICALL
Java_org_mozilla_jss_pkcs11_PK11SymKey_getKeyData
    (JNIEnv *env, jobject this)
{
    PK11SymKey *key=NULL;
    SECItem *keyData; /* a reference to the key data */
    jbyteArray dataArray=NULL;

    /* get the key pointer */
    if( JSS_PK11_getSymKeyPtr(env, this, &key) != PR_SUCCESS) {
        goto finish;
    }

    /* Extract the key data */
    if( PK11_ExtractKeyValue(key) != SECSuccess ) {
        /* key is not extractable */
        JSS_throwMsg(env, NOT_EXTRACTABLE_EXCEPTION, "Unable to extract "
            "symmetric key data");
        goto finish;
    }
    keyData = PK11_GetKeyData(key);
    /* PK11_ExtractKeyValue should have failed if keyData is NULL */
    PR_ASSERT(keyData != NULL);

    /* copy the key data into a Java byte array */
    dataArray = JSS_SECItemToByteArray(env, keyData);

finish:
    /* keyData is just a reference, nothing to free */
    if( dataArray == NULL) {
        PR_ASSERT( (*env)->ExceptionOccurred(env) );
    }
    return dataArray;
}

/***********************************************************************
 *
 * PK11SymKey.getKeyType
 */
JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_pkcs11_PK11SymKey_getKeyType
    (JNIEnv *env, jobject this)
{
    PK11SymKey *key=NULL;
    CK_MECHANISM_TYPE keyMech;
    char *typeFieldName=NULL;
    jclass typeClass=NULL;
    jfieldID typeField=NULL;
    jobject typeObject=NULL;

    if( JSS_PK11_getSymKeyPtr(env, this, &key) != PR_SUCCESS ) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    /* Look up the key type from the key */
    keyMech = PK11_GetMechanism(key);
    switch(keyMech) {
      /* PBE mechanisms have to be handled by hand */
      case CKM_PBE_MD2_DES_CBC:
      case CKM_PBE_MD5_DES_CBC:
      case CKM_NETSCAPE_PBE_SHA1_DES_CBC:
        typeFieldName = DES_KEYTYPE_FIELD;
        break;
      case CKM_PBE_SHA1_RC4_128:
      case CKM_PBE_SHA1_RC4_40:
        typeFieldName = RC4_KEYTYPE_FIELD;
        break;
      case CKM_PBE_SHA1_RC2_128_CBC:
      case CKM_PBE_SHA1_RC2_40_CBC:
        typeFieldName = RC2_KEYTYPE_FIELD;
        break;
      case CKM_PBE_SHA1_DES3_EDE_CBC:
        typeFieldName = DES3_KEYTYPE_FIELD;
        break;
      case CKM_PBA_SHA1_WITH_SHA1_HMAC:
        typeFieldName = SHA1_HMAC_KEYTYPE_FIELD;
        break;
      default:
        keyMech = PK11_GetKeyType( keyMech, 0 );
        switch(keyMech) {
          case CKK_DES:
            typeFieldName = DES_KEYTYPE_FIELD;
            break;
          case CKK_DES3:
            typeFieldName = DES3_KEYTYPE_FIELD;
            break;
          case CKK_RC4:
            typeFieldName = RC4_KEYTYPE_FIELD;
            break;
          case CKK_RC2:
            typeFieldName = RC2_KEYTYPE_FIELD;
            break;
          case CKK_AES:
            typeFieldName = AES_KEYTYPE_FIELD;
            break;
          case CKK_DES2:
             typeFieldName = DES3_KEYTYPE_FIELD;
             break;
          case CKK_GENERIC_SECRET:
             typeFieldName = GENERIC_SECRET_KEYTYPE_FIELD;
             break;
          default:
            PR_ASSERT(PR_FALSE);
            typeFieldName = DES_KEYTYPE_FIELD;
            break;
        }
        break;
    }

    /* convert to a Java key type */
    typeClass = (*env)->FindClass(env, KEYTYPE_CLASS_NAME);
    if(typeClass == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    typeField = (*env)->GetStaticFieldID(env, typeClass, typeFieldName,
        KEYTYPE_FIELD_SIG);
    if(typeField == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    typeObject = (*env)->GetStaticObjectField(env, typeClass, typeField);
    if(typeObject == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

finish:
    return typeObject;
}


/***********************************************************************
 *
 * J S S _ P K 1 1 _ g e t S y m K e y P t r
 *
 */
PRStatus
JSS_PK11_getSymKeyPtr(JNIEnv *env, jobject symKeyObject, PK11SymKey **ptr)
{
    PR_ASSERT(env!=NULL && symKeyObject!=NULL);

    /* Get the pointer from the key proxy */
    return JSS_getPtrFromProxyOwner(env, symKeyObject, SYM_KEY_PROXY_FIELD,
        SYM_KEY_PROXY_SIG, (void**)ptr);
}


/***********************************************************************
 *
 * SymKeyProxy.releaseNativeResources
 */
JNIEXPORT void JNICALL
Java_org_mozilla_jss_pkcs11_SymKeyProxy_releaseNativeResources
    (JNIEnv *env, jobject this)
{
    PK11SymKey *key=NULL;

    PR_ASSERT(env!=NULL && this!=NULL);

    if( JSS_getPtrFromProxy(env, this, (void**)&key) == PR_SUCCESS) {
        PK11_FreeSymKey(key);
    } else {
        /* can't really throw an exception from a destructor */
        PR_ASSERT(PR_FALSE);
    }
}
