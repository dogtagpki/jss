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

#include "_jni/org_mozilla_jss_pkcs11_PK11KeyPairGenerator.h"

#include <pk11func.h>
#include <pk11pqg.h>
#include <nspr.h>
#include <key.h>
#include <secitem.h>

#include <jssutil.h>
#include <pk11util.h>
#include <java_ids.h>
#include <jss_exceptions.h>
#include <jss_bigint.h>


/***********************************************************************
 *
 * k e y s T o K e y P a i r
 *
 * Turns a SECKEYPrivateKey and a SECKEYPublicKey into a Java KeyPair
 * object.
 *
 * INPUTS
 *      pPrivk
 *          Address of a SECKEYPrivateKey* which will be consumed by the
 *          KeyPair.  The pointer will be set to NULL. It is not necessary
 *          to free this private key if the function exits successfully.
 *      pPubk
 *          Address of a SECKEYPublicKey* which will be consumed by this
 *          KeyPair.  The pointer will be set to NULL. It is not necessary
 *          to free this public key if the function exits successfully.
 */
static jobject
keysToKeyPair(JNIEnv *env, SECKEYPrivateKey **pPrivk,
    SECKEYPublicKey **pPubk)
{
    jobject privateKey;
    jobject publicKey;
    jobject keyPair=NULL;
    jclass keyPairClass;
    jmethodID keyPairConstructor;

    /**************************************************
     * wrap the keys in Java objects
     *************************************************/
    publicKey = JSS_PK11_wrapPubKey(env, pPubk);
    privateKey = JSS_PK11_wrapPrivKey(env, pPrivk);

    if(publicKey==NULL || privateKey==NULL) {
        PR_ASSERT( (*env)->ExceptionOccurred(env) != NULL);
        goto finish;
    }

    /**************************************************
     * encapsulate the keys in a keypair
     *************************************************/
    keyPairClass = (*env)->FindClass(env, KEY_PAIR_CLASS_NAME);
    if(keyPairClass == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }
    keyPairConstructor = (*env)->GetMethodID(   env,
                                                keyPairClass,
                                                KEY_PAIR_CONSTRUCTOR_NAME,
                                                KEY_PAIR_CONSTRUCTOR_SIG);
    if(keyPairConstructor == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }
    keyPair = (*env)->NewObject(env,
                                keyPairClass,
                                keyPairConstructor,
                                publicKey,
                                privateKey);
    if(keyPair == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }
        

finish:
    return keyPair;
}

int PK11_NumberObjectsFor(PK11SlotInfo*, CK_ATTRIBUTE*, int);

/*
 * make a common key gen function for both this file and PK11Token.c
 */
SECStatus
JSS_PK11_generateKeyPair(JNIEnv *env, CK_MECHANISM_TYPE mechanism, 
    PK11SlotInfo *slot, SECKEYPublicKey **pubk, SECKEYPrivateKey **privk,
    void *params, PRBool temporary, jint sensitive, jint extractable)
{
    PK11AttrFlags attrFlags = 0;
    *privk=NULL;
    *pubk=NULL;

    PR_ASSERT(env!=NULL && slot!=NULL);

    /**************************************************
     * login to the token if necessary
     *************************************************/
    if( PK11_Authenticate(slot, PR_TRUE /*loadcerts*/, NULL)
           != SECSuccess)
    {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "unable to login to token");
        goto finish;
    }

    /**************************************************
     * generate the key pair on the token
     *************************************************/
    if( temporary ) {
        attrFlags |= PK11_ATTR_SESSION;
    } else {
        attrFlags |= PK11_ATTR_TOKEN;
    }
    if( extractable == 1 ) {
        attrFlags |= PK11_ATTR_EXTRACTABLE;
    } else if( extractable == 0 ) {
        attrFlags |= PK11_ATTR_UNEXTRACTABLE;
    }
    /*
     * The default of sensitive is set this way to be backward
     * compatible.
     */
    if( sensitive == -1 ) {
        sensitive = !temporary;
    }
    /*
     * The PRIVATE/PUBLIC attributes are set this way to be backward
     * compatible with the original PK11_GenerateKeyPair call.
     */
    if( sensitive ) {
        attrFlags |= (PK11_ATTR_SENSITIVE | PK11_ATTR_PRIVATE);
    } else {
        attrFlags |= (PK11_ATTR_INSENSITIVE | PK11_ATTR_PUBLIC);
    }
    *privk = PK11_GenerateKeyPairWithFlags(slot,
                                          mechanism,
                                          params, 
                                          pubk,
                                          attrFlags,
                                          NULL /* default PW callback */ );
    if( *privk == NULL ) {
        int errLength;
        char *errBuf;
        char *msgBuf;

        errLength = PR_GetErrorTextLength();
        if(errLength > 0) {
            errBuf = PR_Malloc(errLength);
            if(errBuf == NULL) {
                JSS_throw(env, OUT_OF_MEMORY_ERROR);
                goto finish;
            }
            PR_GetErrorText(errBuf);
        }
        msgBuf = PR_smprintf("Keypair Generation failed on token: %s",
            errLength>0? errBuf : "");
        if(errLength>0) {
            PR_Free(errBuf);
        }
        JSS_throwMsg(env, TOKEN_EXCEPTION, msgBuf);
        PR_Free(msgBuf);
        goto finish;
    }
    return SECSuccess;


finish:
    if(*privk!=NULL) {
        SECKEY_DestroyPrivateKey(*privk);
	*privk = NULL;
    }
    if(*pubk!=NULL) {
        SECKEY_DestroyPublicKey(*pubk);
	*pubk = NULL;
    }
    return SECFailure;
}

/**********************************************************************
 * Local generic helper
 */
static jobject 
PK11KeyPairGenerator(JNIEnv *env, jobject this, jobject token, 
    CK_MECHANISM_TYPE mechanism, void *params, 
    jboolean temporary, jint sensitive, jint extractable)
{
    PK11SlotInfo* slot;
    SECKEYPrivateKey *privk=NULL;
    SECKEYPublicKey *pubk=NULL;
    jobject keyPair=NULL;
    SECStatus rv;

    PR_ASSERT(env!=NULL && this!=NULL && token!=NULL);

    /**************************************************
     * get the slot pointer
     *************************************************/
    if( JSS_PK11_getTokenSlotPtr(env, token, &slot) != PR_SUCCESS) {
        PR_ASSERT( (*env)->ExceptionOccurred(env) != NULL);
        goto finish;
    }
    PR_ASSERT(slot != NULL);

    rv = JSS_PK11_generateKeyPair(env, mechanism, slot, &pubk, &privk,
    	params, temporary, sensitive, extractable);
    if (rv != SECSuccess) {
        goto finish;
    }

    /**************************************************
     * wrap in a Java KeyPair object
     *************************************************/
    keyPair = keysToKeyPair(env, &privk, &pubk);
    if(keyPair == NULL ) {
        PR_ASSERT( (*env)->ExceptionOccurred(env) != NULL);
        goto finish;
    }

finish:
    if(privk!=NULL) {
        SECKEY_DestroyPrivateKey(privk);
    }
    if(pubk!=NULL) {
        SECKEY_DestroyPublicKey(pubk);
    }
    return keyPair;
}

/**********************************************************************
 * PK11KeyPairGenerator.generateRSAKeyPair
 */
JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_pkcs11_PK11KeyPairGenerator_generateRSAKeyPair
  (JNIEnv *env, jobject this, jobject token, jint keySize, jlong publicExponent,
    jboolean temporary, jint sensitive, jint extractable)
{
    PK11RSAGenParams params;

    PR_ASSERT(env!=NULL && this!=NULL && token!=NULL);

    /**************************************************
     * setup parameters
     *************************************************/
    params.keySizeInBits = keySize;
    params.pe = publicExponent;

    return PK11KeyPairGenerator(env, this, token, CKM_RSA_PKCS_KEY_PAIR_GEN,
     &params, temporary, sensitive, extractable);
}

#define ZERO_SECITEM(item) {(item).len=0; (item).data=NULL;}

/**********************************************************************
 *
 * PK11KeyPairGenerator.generateDSAKeyPair
 *
 */
JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_pkcs11_PK11KeyPairGenerator_generateDSAKeyPair
  (JNIEnv *env, jobject this, jobject token, jbyteArray P, jbyteArray Q,
    jbyteArray G, jboolean temporary, jint sensitive, jint extractable)
{
    SECItem p, q, g;
    PQGParams *params=NULL;
    jobject keyPair=NULL;

    PR_ASSERT(env!=NULL && this!=NULL && token!=NULL && P!=NULL && Q!=NULL
                && G!=NULL);

    /* zero these so we can free them indiscriminately later */
    ZERO_SECITEM(p);
    ZERO_SECITEM(q);
    ZERO_SECITEM(g);

    /**************************************************
     * Setup the parameters
     *************************************************/
    if( JSS_ByteArrayToOctetString(env, P, &p) ||
        JSS_ByteArrayToOctetString(env, Q, &q) ||
        JSS_ByteArrayToOctetString(env, G, &g) )
    {
        PR_ASSERT( (*env)->ExceptionOccurred(env) != NULL);
        goto finish;
    }
    params = PK11_PQG_NewParams(&p, &q, &g);
    if(params == NULL) {
        JSS_throw(env, OUT_OF_MEMORY_ERROR);
        goto finish;
    }
    keyPair = PK11KeyPairGenerator(env, this, token, CKM_DSA_KEY_PAIR_GEN,
     			params, temporary, sensitive, extractable);

finish:
    SECITEM_FreeItem(&p, PR_FALSE);
    SECITEM_FreeItem(&q, PR_FALSE);
    SECITEM_FreeItem(&g, PR_FALSE);
    PK11_PQG_DestroyParams(params);
    return keyPair;
}

void
DumpItem(SECItem *item)
{
  unsigned char *data = item->data;
  int i;

  for (i=0; i < item->len; i++) {
    printf(" %02x",data[i]);
  }
  printf(" : 0x%08x %d\n", data, item->len);
}

/**********************************************************************
 *
 * PK11KeyPairGenerator.generateECKeyPair
 *
 */
JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_pkcs11_PK11KeyPairGenerator_generateECKeyPair
  (JNIEnv *env, jobject this, jobject token, jbyteArray Curve, 
    jboolean temporary, jint sensitive, jint extractable)
{
    SECItem curve;
    jobject keyPair=NULL;

    PR_ASSERT(env!=NULL && this!=NULL && token!=NULL && Curve!=NULL );

    /* zero these so we can free them indiscriminately later */
    ZERO_SECITEM(curve);

    /**************************************************
     * Setup the parameters
     *************************************************/
    if( JSS_ByteArrayToOctetString(env, Curve, &curve))
    {
        PR_ASSERT( (*env)->ExceptionOccurred(env) != NULL);
        goto finish;
    }

    keyPair = PK11KeyPairGenerator(env, this, token, CKM_EC_KEY_PAIR_GEN,
     			&curve, temporary, sensitive, extractable);

finish:
    SECITEM_FreeItem(&curve, PR_FALSE);
    return keyPair;
}
