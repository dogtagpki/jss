/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "_jni/org_mozilla_jss_SecretDecoderRing_KeyManager.h"
#include <nspr.h>
#include <secitem.h>
#include <jss_exceptions.h>
#include <jssutil.h>
#include <pk11func.h>
#include <pk11util.h>
#include <Algorithm.h>

JNIEXPORT void JNICALL
Java_org_mozilla_jss_SecretDecoderRing_KeyManager_generateKeyNative
    (JNIEnv *env, jobject this, jobject tokenObj, jobject algObj,
    jbyteArray keyIDba, jint keySize)
{
    PK11SlotInfo *slot = NULL;
    CK_MECHANISM_TYPE mech;
    PK11SymKey *symk = NULL;
    SECItem *keyID = NULL;

    /* get the slot */
    if( JSS_PK11_getTokenSlotPtr(env, tokenObj, &slot) != PR_SUCCESS ) {
        goto finish;
    }

    if( PK11_Authenticate(slot, PR_TRUE /*load certs*/, NULL /*wincx*/)
        != SECSuccess)
    {
        JSS_throwMsgPrErr(env, TOKEN_EXCEPTION,
            "Failed to login to token");
        goto finish;
    }

    /* get the key ID */
    keyID = JSS_ByteArrayToSECItem(env, keyIDba);
    if( keyID == NULL ) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    /* get the algorithm */
    mech = JSS_getPK11MechFromAlg(env, algObj);
    if( mech == CKM_INVALID_MECHANISM) {
        JSS_throwMsgPrErr(env, TOKEN_EXCEPTION, "Failed to find PKCS #11 "
            "mechanism for key generation algorithm");
        goto finish;
    }

    /* generate the key */
    symk = PK11_TokenKeyGen(slot, mech, NULL /*param*/, keySize, keyID,
        PR_TRUE /* isToken */, NULL /*wincx*/);
    if( symk == NULL ) {
        JSS_throwMsgPrErr(env, TOKEN_EXCEPTION,
            "Failed to generate token symmetric key");
        goto finish;
    }


finish:
    if( symk != NULL ) {
        PK11_FreeSymKey(symk);
    }
    if( keyID != NULL ) {
        SECITEM_FreeItem(keyID, PR_TRUE /*freeit*/);
    }
    return;
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_SecretDecoderRing_KeyManager_generateUniqueNamedKeyNative
    (JNIEnv *env, jobject this, jobject tokenObj, jobject algObj,
    jbyteArray keyIDba, jint keySize, jstring nickname)
{
    PK11SlotInfo *slot = NULL;
    CK_MECHANISM_TYPE mech;
    PK11SymKey *symk = NULL;
    SECItem *keyID = NULL;
    const char *keyname = NULL;
    SECStatus status;

    /* get the slot */
    if( JSS_PK11_getTokenSlotPtr(env, tokenObj, &slot) != PR_SUCCESS ) {
        goto finish;
    }

    if( PK11_Authenticate(slot, PR_TRUE /*load certs*/, NULL /*wincx*/)
        != SECSuccess)
    {
        JSS_throwMsgPrErr(env, TOKEN_EXCEPTION,
            "Failed to login to token");
        goto finish;
    }

    /* get the key ID */
    keyID = JSS_ByteArrayToSECItem(env, keyIDba);
    if( keyID == NULL ) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    /* get the algorithm */
    mech = JSS_getPK11MechFromAlg(env, algObj);
    if( mech == CKM_INVALID_MECHANISM) {
        JSS_throwMsgPrErr(env, TOKEN_EXCEPTION, "Failed to find PKCS #11 "
            "mechanism for key generation algorithm");
        goto finish;
    }

    /* generate the key */
    symk = PK11_TokenKeyGen(slot, mech, NULL /*param*/, keySize, keyID,
        PR_TRUE /* isToken */, NULL /*wincx*/);
    if( symk == NULL ) {
        JSS_throwMsgPrErr(env, TOKEN_EXCEPTION,
            "Failed to generate token symmetric key");
        goto finish;
    }

    /* convert the Java String into a native "C" string */
    keyname = (*env)->GetStringUTFChars( env, nickname, 0 );

    /* name the key */
    status = PK11_SetSymKeyNickname( symk, keyname );
    if( status != SECSuccess ) {
        JSS_throwMsgPrErr(env, TOKEN_EXCEPTION,
            "Failed to name token symmetric key");
    }


finish:
    if( symk != NULL ) {
        PK11_FreeSymKey(symk);
    }
    if( keyID != NULL ) {
        SECITEM_FreeItem(keyID, PR_TRUE /*freeit*/);
    }
    if( keyname != NULL ) {
        /* free the native "C" string */
        (*env)->ReleaseStringUTFChars(env, nickname, keyname);
    }
    return;
}

JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_SecretDecoderRing_KeyManager_lookupKeyNative
    (JNIEnv *env, jobject this, jobject tokenObj, jobject algObj,
    jbyteArray keyIDba)
{
    PK11SlotInfo *slot = NULL;
    PK11SymKey *symk = NULL;
    SECItem *keyID = NULL;
    jobject symkObj = NULL;
    CK_MECHANISM_TYPE mech;

    /* get the slot */
    if( JSS_PK11_getTokenSlotPtr(env, tokenObj, &slot) != PR_SUCCESS ) {
        goto finish;
    }

    if( PK11_Authenticate(slot, PR_TRUE /*load certs*/, NULL /*wincx*/)
        != SECSuccess)
    {
        JSS_throwMsgPrErr(env, TOKEN_EXCEPTION,
            "Failed to login to token");
        goto finish;
    }

    /* get the key ID */
    keyID = JSS_ByteArrayToSECItem(env, keyIDba);
    if( keyID == NULL ) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    /* get the algorithm */
    mech = JSS_getPK11MechFromAlg(env, algObj);
    if( mech == CKM_INVALID_MECHANISM) {
        JSS_throwMsgPrErr(env, TOKEN_EXCEPTION, "Failed to find PKCS #11 "
            "mechanism for key generation algorithm");
        goto finish;
    }

    symk = PK11_FindFixedKey(slot, mech, keyID, NULL /*wincx*/);
    if( symk != NULL ) {
        symkObj = JSS_PK11_wrapSymKey(env, &symk);
    }

finish:
    if( symk != NULL ) {
        PK11_FreeSymKey(symk);
    }
    if( keyID != NULL ) {
        SECITEM_FreeItem(keyID, PR_TRUE /*freeit*/);
    }
    return symkObj;
}

JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_SecretDecoderRing_KeyManager_lookupUniqueNamedKeyNative
    (JNIEnv *env, jobject this, jobject tokenObj, jobject algObj,
    jstring nickname)
{
    PK11SlotInfo *slot = NULL;
    CK_MECHANISM_TYPE mech;
    const char *keyname = NULL;
    char *name = NULL;
    int count = 0;
    int keys_found = 0;
    PK11SymKey *symKey = NULL;
    PK11SymKey *nextSymKey = NULL;
    jobject symKeyObj = NULL;

    /* get the slot */
    if( JSS_PK11_getTokenSlotPtr(env, tokenObj, &slot) != PR_SUCCESS ) {
        goto finish;
    }

    if( PK11_Authenticate(slot, PR_TRUE /*load certs*/, NULL /*wincx*/)
        != SECSuccess)
    {
        JSS_throwMsgPrErr(env, TOKEN_EXCEPTION,
            "Failed to login to token");
        goto finish;
    }

    /* get the algorithm -- although this is not currently used */
    mech = JSS_getPK11MechFromAlg(env, algObj);
    if( mech == CKM_INVALID_MECHANISM) {
        JSS_throwMsgPrErr(env, TOKEN_EXCEPTION, "Failed to find PKCS #11 "
            "mechanism for key generation algorithm");
        goto finish;
    }

    /* convert the Java String into a native "C" string */
    keyname = (*env)->GetStringUTFChars( env, nickname, 0 );

    /* initialize the symmetric key list. */
    symKey = PK11_ListFixedKeysInSlot(
             /* slot     */            slot,
             /* nickname */            NULL,
             /* wincx    */            NULL );

    /* iterate through the symmetric key list. */
    while( symKey != NULL ) {
        name = PK11_GetSymKeyNickname( /* symmetric key */  symKey );
        if( name != NULL ) {
            if( keyname != NULL ) {
                if( PL_strcmp( keyname, name ) == 0 ) {
                    keys_found++;
                }
            }
            PORT_Free(name);
        }

        nextSymKey = PK11_GetNextSymKey( /* symmetric key */  symKey );
        PK11_FreeSymKey( /* symmetric key */  symKey );
        symKey = nextSymKey;

        count++;
    }

    /* case 1:  the token is empty */
    if( count == 0 ) {
        /* the specified token is empty */
        goto finish;
    }

    /* case 2:  the specified key is not on this token */
    if( ( keyname != NULL ) &&
        ( keys_found == 0 ) ) {
        /* the key called "keyname" could not be found */
        goto finish;
    }

    /* case 3:  the specified key exists more than once on this token */
    if( keys_found != 1 ) {
        /* more than one key called "keyname" was found on this token */
        JSS_throwMsgPrErr(env, TOKEN_EXCEPTION,
            "Duplicate named keys exist on this token");
        goto finish;
    }

    /* Re-initialize the symmetric key list. */
    symKey = PK11_ListFixedKeysInSlot(
             /* slot     */            slot,
             /* nickname */            NULL,
             /* wincx    */            NULL );

    /* Reiterate through the symmetric key list once more, */
    /* this time returning an actual reference to the key. */
    while( symKey != NULL ) {
        name = PK11_GetSymKeyNickname( /* symmetric key */  symKey );
        if( name != NULL ) {
            if( keyname != NULL ) {
                if( PL_strcmp( keyname, name ) == 0 ) {
                    symKeyObj = JSS_PK11_wrapSymKey(env, &symKey);
                    PORT_Free(name);
                    goto finish;
                }
            }
            PORT_Free(name);
        }

        nextSymKey = PK11_GetNextSymKey( /* symmetric key */  symKey );
        PK11_FreeSymKey( /* symmetric key */  symKey );
        symKey = nextSymKey;
    }


finish:
    if( symKey != NULL ) {
        PK11_FreeSymKey(symKey);
    }
    if( keyname != NULL ) {
        /* free the native "C" string */
        (*env)->ReleaseStringUTFChars(env, nickname, keyname);
    }
    return symKeyObj;
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_SecretDecoderRing_KeyManager_deleteKeyNative
    (JNIEnv *env, jobject this, jobject tokenObj, jobject key)
{
    PK11SlotInfo *slot = NULL;
    PK11SymKey *symk = NULL;

    /* get the slot */
    if( JSS_PK11_getTokenSlotPtr(env, tokenObj, &slot) != PR_SUCCESS ) {
        goto finish;
    }

    if( PK11_Authenticate(slot, PR_TRUE /*load certs*/, NULL /*wincx*/)
        != SECSuccess)
    {
        JSS_throwMsgPrErr(env, TOKEN_EXCEPTION,
            "Failed to login to token");
        goto finish;
    }

    /* get the key pointer */
    if( JSS_PK11_getSymKeyPtr(env, key, &symk) != PR_SUCCESS) {
        goto finish;
    }

    if( PK11_DeleteTokenSymKey(symk) != SECSuccess ) {
        JSS_throwMsgPrErr(env, TOKEN_EXCEPTION,
            "Failed to delete token symmetric key");
        goto finish;
    }

finish:
    /* don't free symk or slot, they are owned by their Java objects */
    return;
}
