/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "_jni/org_mozilla_jss_pkcs11_PK11KeyWrapper.h"

#include <nspr.h>
#include <plarena.h>
#include <seccomon.h>
#include <pk11func.h>
#include <secitem.h>
#include <keythi.h>

/* JSS includes */
#include <java_ids.h>
#include <jss_exceptions.h>
#include <jssutil.h>
#include <pk11util.h>
#include <Algorithm.h>
#include "StaticVoidPointer.h"
#include "jssconfig.h"

#define MAX_PRIVATE_KEY_LEN     MAX_RSA_MODULUS_LEN

/*
 * This is bytes, not bits.  A 2048-bit wrapped RSA private key takes up around
 * 1200 bytes, because lots of "helper" values are stored along with the
 * modulus and exponent. 4096 bytes will hold at least a 4096-bit RSA key.
 */
#define MAX_WRAPPED_KEY_LEN     4096

/***********************************************************************
 *
 * PK11KeyWrapper.nativeWrapSymWithSym
 */
JNIEXPORT jbyteArray JNICALL
Java_org_mozilla_jss_pkcs11_PK11KeyWrapper_nativeWrapSymWithSym
    (JNIEnv *env, jobject this, jobject tokenObj, jobject toBeWrappedObj,
        jobject wrappingKeyObj, jobject algObj, jbyteArray ivBA)
{
    PK11SymKey *wrapping = NULL;
    PK11SymKey *toBeWrapped = NULL;
    CK_MECHANISM_TYPE mech;
    SECItem wrapped;
    jbyteArray wrappedBA=NULL;
    SECItem *iv=NULL, *param=NULL;
    SECStatus status;

    /* initialize so we can goto finish */
    wrapped.data = NULL;
    wrapped.len = 0;

    /* get wrapping key */
    if( JSS_PK11_getSymKeyPtr(env, wrappingKeyObj, &wrapping)!= PR_SUCCESS) {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "Unable to extract symmetric "
                "wrapping key");
        return NULL;
    }

    /* get toBeWrapped key */
    if( JSS_PK11_getSymKeyPtr(env, toBeWrappedObj, &toBeWrapped) != PR_SUCCESS){
        JSS_throwMsg(env, TOKEN_EXCEPTION, "Unable to extract symmetric "
            "to be wrapped key");
        return NULL;
    }

    /* get the mechanism */
    mech = JSS_getPK11MechFromAlg(env, algObj);
    if(mech == CKM_INVALID_MECHANISM) {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "Unrecognized algorithm");
        goto finish;
    }

    /* get the parameter */
    if( ivBA ) {
        iv = JSS_ByteArrayToSECItem(env, ivBA);
        if( iv == NULL ) {
            goto finish; /* exception was thrown */
        }
        param = PK11_ParamFromIV(mech, iv);
        if( param == NULL ) {
            JSS_throwMsg(env, TOKEN_EXCEPTION, "Unable to create mechanism"
                " parameter from initialization vector");
            goto finish;
        }
    }

    /* setup space for wrapped key */
    wrapped.len = MAX_WRAPPED_KEY_LEN; /* yuk! */
    wrapped.data = PR_Malloc(wrapped.len);
    if(wrapped.data == NULL) {
        JSS_throw(env, OUT_OF_MEMORY_ERROR);
        goto finish;
    }

    /* perform the wrap */
    status = PK11_WrapSymKey(mech, param, wrapping, toBeWrapped, &wrapped);
    if( status != SECSuccess ) {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "Wrap operation failed on token");
        goto finish;
    }

    /* package the wrapped data into a byte array */
    wrappedBA = JSS_SECItemToByteArray(env, &wrapped);

finish:
    if(iv) {
        SECITEM_FreeItem(iv, PR_TRUE /*freeit*/);
    }
    if(param) {
        SECITEM_FreeItem(param, PR_TRUE /*freeit*/);
    }
    SECITEM_FreeItem(&wrapped, PR_FALSE /*freeit*/);

    return wrappedBA;
}

/***********************************************************************
 *
 * PK11KeyWrapper.nativeWrapSymWithPub
 */
JNIEXPORT jbyteArray JNICALL
Java_org_mozilla_jss_pkcs11_PK11KeyWrapper_nativeWrapSymWithPub
    (JNIEnv *env, jobject this, jobject tokenObj, jobject toBeWrappedObj,
        jobject wrappingKeyObj, jobject algObj, jobject paramsPtr,
        jlong paramsSize)
{
    SECKEYPublicKey *wrapping = NULL;
    PK11SymKey *toBeWrapped = NULL;
    CK_MECHANISM_TYPE mech;
    CK_VOID_PTR params = NULL;
    SECItem paramItem;
    SECItem *paramsItemPtr = NULL;
    SECItem wrapped;
    jbyteArray wrappedBA=NULL;
    SECStatus status;

    /* initialize so we can goto finish */
    wrapped.data = NULL;
    wrapped.len = 0;

    /* get wrapping key */
    if( JSS_PK11_getPubKeyPtr(env, wrappingKeyObj, &wrapping)!= PR_SUCCESS) {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "Unable to extract public "
                "wrapping key");
        return NULL;
    }

    /* get toBeWrapped key */
    if( JSS_PK11_getSymKeyPtr(env, toBeWrappedObj, &toBeWrapped) != PR_SUCCESS){
        JSS_throwMsg(env, TOKEN_EXCEPTION, "Unable to extract symmetric "
            "to be wrapped key");
        return NULL;
    }

    if (paramsPtr != NULL) {
        if (JSS_PR_getStaticVoidRef(env, paramsPtr, &params) != PR_SUCCESS) {
            JSS_throwMsg(env, TOKEN_EXCEPTION, "Unable to extract parameters "
                "to pass with the wrapping mechanism");
            return NULL;
        }
    }

    /* get the mechanism */
    mech = JSS_getPK11MechFromAlg(env, algObj);
    if(mech == CKM_INVALID_MECHANISM) {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "Unrecognized algorithm");
        goto finish;
    }

    /* setup space for wrapped key */
    wrapped.len = MAX_WRAPPED_KEY_LEN; /* yuk! */
    wrapped.data = PR_Malloc(wrapped.len);
    if(wrapped.data == NULL) {
        JSS_throw(env, OUT_OF_MEMORY_ERROR);
        goto finish;
    }

    if (params != NULL && paramsSize != 0) {
        /* Only provision parameters when present. */
        paramItem.data = params;
        paramItem.len = paramsSize;
        paramsItemPtr = &paramItem;
    }

    /* perform the wrap */
#ifdef HAVE_NSS_OAEP
    status = PK11_PubWrapSymKeyWithMechanism(wrapping, mech, paramsItemPtr, toBeWrapped, &wrapped);
#else
    if (mech == CKM_RSA_PKCS_OAEP) {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "RSA-OAEP not supported by the NSS version used to build JSS");
        goto finish;
    }

    status = PK11_PubWrapSymKey(mech, wrapping, toBeWrapped, &wrapped);
#endif
    if( status != SECSuccess ) {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "Wrap operation failed on token");
        goto finish;
    }

    /* package the wrapped data into a byte array */
    wrappedBA = JSS_SECItemToByteArray(env, &wrapped);

finish:
    SECITEM_FreeItem(&wrapped, PR_FALSE /*freeit*/);

    return wrappedBA;
}


/***********************************************************************
 *
 * PK11KeyWrapper.nativeWrapPrivWithSym
 */
JNIEXPORT jbyteArray JNICALL
Java_org_mozilla_jss_pkcs11_PK11KeyWrapper_nativeWrapPrivWithSym
    (JNIEnv *env, jobject this, jobject tokenObj, jobject toBeWrappedObj,
        jobject wrappingKeyObj, jobject algObj, jbyteArray ivBA)
{
    PK11SymKey *wrapping = NULL;
    SECKEYPrivateKey *toBeWrapped= NULL;
    CK_MECHANISM_TYPE mech;
    SECStatus status;
    SECItem wrapped;
    PK11SlotInfo *slot=NULL;
    jbyteArray wrappedBA=NULL;
    SECItem *iv=NULL, *param=NULL;

    /* setup space for wrapped key */
    wrapped.len = MAX_WRAPPED_KEY_LEN;
    wrapped.data = PR_Malloc(wrapped.len);
    if(wrapped.data == NULL) {
        wrapped.len = 0;
        JSS_throw(env, OUT_OF_MEMORY_ERROR);
        goto finish;
    }

    /* get wrapping key */
    if( JSS_PK11_getSymKeyPtr(env, wrappingKeyObj, &wrapping) != PR_SUCCESS) {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "Unable to extract symmetric "
                "wrapping key");
        return NULL;
    }

    /* get toBeWrapped key */
    if( JSS_PK11_getPrivKeyPtr(env, toBeWrappedObj, &toBeWrapped) !=PR_SUCCESS){
        JSS_throwMsg(env, TOKEN_EXCEPTION, "Unable to extract private "
            "to be wrapped key");
        return NULL;
    }

    /* get the slot */
    if( JSS_PK11_getTokenSlotPtr(env, tokenObj, &slot) != PR_SUCCESS) {
        /* exception was thrown */
        goto finish;
    }

    /* Get the wrapping mechanism */
    mech = getSupportedWrappingMechanism(env, algObj, slot);
    if(mech == CKM_INVALID_MECHANISM) {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "Unrecognized algorithm");
        goto finish;
    }

    /* get the mechanism parameter (IV) */
    if( ivBA ) {
        iv = JSS_ByteArrayToSECItem(env, ivBA);
        if( iv == NULL ) {
            goto finish; /* exception was thrown */
        }
        param = PK11_ParamFromIV(mech, iv);
        if( param == NULL ) {
            JSS_throwMsg(env, TOKEN_EXCEPTION,
                "Failed to convert initialization vector to parameter");
            goto finish;
        }
    }

    /* perform the wrap operation */
    status = PK11_WrapPrivKey(slot, wrapping, toBeWrapped, mech, param,
                &wrapped, NULL /* wincx */ );
    if(status != SECSuccess) {
        JSS_throwMsgPrErr(env, TOKEN_EXCEPTION, "Wrapping operation failed on token");
        goto finish;
    }
    PR_ASSERT(wrapped.len>0 && wrapped.data!=NULL);

    /* package the wrapped data into a byte array */
    wrappedBA = JSS_SECItemToByteArray(env, &wrapped);
    /* fall through if an exception occurs */

finish:
    if(iv) {
        SECITEM_FreeItem(iv, PR_TRUE /*freeit*/);
    }
    if(param) {
        SECITEM_FreeItem(param, PR_TRUE /*freeit*/);
    }
    SECITEM_FreeItem(&wrapped, PR_FALSE /*freeit*/);

    return wrappedBA;
}

/***********************************************************************
 *
 * PK11KeyWrapper.nativeUnwrapPrivWithSym
 */
JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_pkcs11_PK11KeyWrapper_nativeUnwrapPrivWithSym
    (JNIEnv *env, jclass clazz, jobject tokenObj, jobject unwrapperObj,
        jbyteArray wrappedBA, jobject wrapAlgObj, jobject typeAlgObj,
        jbyteArray publicValueBA, jbyteArray ivBA, jboolean temporary)
{
    PK11SlotInfo *slot;
    PK11SymKey *unwrappingKey;
    SECKEYPrivateKey *privk=NULL;
    jobject privkObj=NULL;
    CK_MECHANISM_TYPE wrapType, keyTypeMech;
    CK_KEY_TYPE keyType;
    SECItem *wrapped=NULL, *iv=NULL, *param=NULL, *pubValue=NULL;
    SECItem label; /* empty secitem, doesn't need to be freed */
    PRBool token;
    CK_ATTRIBUTE_TYPE attribs[4] = {0, 0, 0, 0};
    int numAttribs = 0;
    CK_TOKEN_INFO tokenInfo;

    /* ideal defaults */
    PRBool isSensitive = PR_TRUE;
    PRBool isExtractable = PR_FALSE;

    /* special case nethsm and lunasa*/
    const int numManufacturerIDchars = 7;
    CK_UTF8CHAR nethsmManufacturerID[] = {'n','C','i','p','h','e','r'};
    CK_UTF8CHAR lunasaManufacturerID[] = {'S','a','f','e','n','e','t'};
    PRBool isNethsm = PR_TRUE;
    PRBool isLunasa = PR_TRUE;

    tokenInfo.manufacturerID[0] = 0;

    if( JSS_PK11_getTokenSlotPtr(env, tokenObj, &slot) != PR_SUCCESS) {
        /* exception was thrown */
        goto finish;
    }

    if ( (PK11_GetTokenInfo(slot, &tokenInfo) == SECSuccess) &&
       (tokenInfo.manufacturerID[0] != 0)) {
        int ix = 0;

        for(ix=0; ix < numManufacturerIDchars; ix++) {
            if (tokenInfo.manufacturerID[ix] != nethsmManufacturerID[ix]) {
               isNethsm = PR_FALSE;
               break;
            }
        }

        for(ix=0; ix < numManufacturerIDchars; ix++) {
            if (tokenInfo.manufacturerID[ix] != lunasaManufacturerID[ix]) {
               isLunasa = PR_FALSE;
               break;
            }
        }
    } else {
        isNethsm = PR_FALSE;
        isLunasa = PR_FALSE;
    }

    /* get unwrapping key */
    if( JSS_PK11_getSymKeyPtr(env, unwrapperObj, &unwrappingKey)
            != PR_SUCCESS) {
        /* exception was thrown */
        goto finish;
    }

    /* Get the wrapping mechanism */
    wrapType = getSupportedWrappingMechanism(env, wrapAlgObj, slot);

    if(wrapType == CKM_INVALID_MECHANISM) {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "Unknown algorithm");
        goto finish;
    }

    /* get the mechanism parameter (IV) */
    if( ivBA ) {
        iv = JSS_ByteArrayToSECItem(env, ivBA);
        if( iv == NULL ) {
            goto finish; /* exception was thrown */
        }
        param = PK11_ParamFromIV(wrapType, iv);
        if( param == NULL ) {
            JSS_throwMsg(env, TOKEN_EXCEPTION,
                "Failed to convert initialization vector to parameter");
            goto finish;
        }
    }

    /* get wrapped key from byte array */
    wrapped = JSS_ByteArrayToSECItem(env, wrappedBA);
    if( wrapped == NULL ) {
        /* exception was thrown */
        goto finish;
    }

    /* initialize the label to be empty */
    label.len = 0;
    label.data = NULL;

    /* get the public value */
    pubValue = JSS_ByteArrayToSECItem(env, publicValueBA);
    if(pubValue == NULL ) {
        /* exception was thrown */
        goto finish;
    }

    if( temporary ) {
        token = PR_FALSE;
    } else {
        token = PR_TRUE;
    }

    /* get key type */
    keyTypeMech = JSS_getPK11MechFromAlg(env, typeAlgObj);
    if( keyTypeMech == CKM_INVALID_MECHANISM ) {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "Unrecognized key type algorithm");
        goto finish;
    }

    keyType = PK11_GetKeyType(keyTypeMech, 0);

    /* special case nethsm and lunasa*/
    if( isNethsm ) {
        isSensitive = PR_FALSE;
        isExtractable = PR_FALSE;
    } else if ( isLunasa) {
        isSensitive = PR_FALSE;
        isExtractable = PR_TRUE;
    }

    /* figure out which operations to enable for this key */
    switch (keyType) {
    case CKK_RSA:
        numAttribs = 3;
        attribs[0] = CKA_SIGN;
        attribs[1] = CKA_SIGN_RECOVER;
        attribs[2] = CKA_UNWRAP;
        if (isExtractable) {
            attribs[3] = CKA_EXTRACTABLE;
            numAttribs = 4;
        }
	break;
    case CKK_EC:
        numAttribs = 1;
        attribs[0] = CKA_SIGN;
        if (isExtractable) {
            attribs[1] = CKA_EXTRACTABLE;
            numAttribs = 2;
        }
	break;
    case CKK_DSA:
        attribs[0] = CKA_SIGN;
        numAttribs = 1;
	break;
    case CKK_KEA:
    case CKK_DH:
    case CKK_X9_42_DH:
        attribs[0] = CKA_DERIVE;
        numAttribs = 1;
	break;
    default:
        /* unknown key type */
        PR_ASSERT(PR_FALSE);
	attribs[0] = CKA_SIGN;
	numAttribs = 1;
	break;
    }

    /* perform the unwrap */
    privk = PK11_UnwrapPrivKey(slot, unwrappingKey, wrapType, param, wrapped,
                &label, pubValue, token, isSensitive /*sensitive*/, keyType,
                attribs, numAttribs, NULL /*wincx*/);
    if( privk == NULL ) {
        char err[256] = {0};
        PR_snprintf(err, 256, "Key Unwrap failed on token; keyType=%d", keyType);
        JSS_throwMsgPrErr(env, TOKEN_EXCEPTION, err);
        goto finish;
    }
                
    /* stuff the privk into a Java private key object. This sets privk to
     * NULL */
    privkObj = JSS_PK11_wrapPrivKey(env, &privk);

finish:
    if(iv) {
        SECITEM_FreeItem(iv, PR_TRUE /*free iv*/);
    }
    if(param) {
        SECITEM_FreeItem(param, PR_TRUE /*free param*/);
    }
    if(wrapped) {
        SECITEM_FreeItem(wrapped, PR_TRUE /*free wrapped*/);
    }
    if(pubValue) {
        SECITEM_FreeItem(pubValue, PR_TRUE /*free pubValue*/);
    }
    PR_ASSERT(privk==NULL);
    PR_ASSERT( privkObj!=NULL || (*env)->ExceptionOccurred(env) );
    return privkObj;
}

#define ALL_SYMKEY_OPS  (CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP)

/***********************************************************************
 *
 * PK11KeyWrapper.nativeUnwrapSymWithSym
 */
JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_pkcs11_PK11KeyWrapper_nativeUnwrapSymWithSym
    (JNIEnv *env, jclass clazz, jobject tokenObj, jobject unwrapperObj,
        jbyteArray wrappedBA, jobject wrapAlgObj, jobject typeAlgObj,
        jint keyLen, jbyteArray ivBA, jint usageEnum, jboolean temporary)
{
    PK11SymKey *symKey=NULL, *wrappingKey=NULL;
    CK_MECHANISM_TYPE wrappingMech, keyTypeMech;
    SECItem *wrappedKey=NULL, *iv=NULL, *param=NULL;
    jobject keyObj = NULL;
    CK_ULONG operation;
    CK_FLAGS flags;
    PRBool isPermanent = PR_FALSE;

    /* get key type */
    keyTypeMech = JSS_getPK11MechFromAlg(env, typeAlgObj);
    if( keyTypeMech == CKM_INVALID_MECHANISM ) {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "Unrecognized key type algorithm");
        goto finish;
    }

    /* get wrapping key */
    if( JSS_PK11_getSymKeyPtr(env, unwrapperObj, &wrappingKey) != PR_SUCCESS) {
        /* exception was thrown */
        goto finish;
    }

    /* get wrapping mechanism */
    wrappingMech = JSS_getPK11MechFromAlg(env, wrapAlgObj);
    if( wrappingMech == CKM_INVALID_MECHANISM ) {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "Unrecognized wrapping algorithm");
        goto finish;
    }

    /* get the mechanism parameter (IV) */
    if (ivBA == NULL) {
        param = PK11_ParamFromIV(wrappingMech,NULL);
    } else {
        iv = JSS_ByteArrayToSECItem(env, ivBA);
        if( iv == NULL ) {
            goto finish; /* exception was thrown */
        }
        param = PK11_ParamFromIV(wrappingMech, iv);
        if( param == NULL ) {
            JSS_throwMsg(env, TOKEN_EXCEPTION,
                "Failed to convert initialization vector to parameter");
            goto finish;
        }
    }

    /* get the wrapped key */
    wrappedKey = JSS_ByteArrayToSECItem(env, wrappedBA);
    if( wrappedKey == NULL ) {
        /* exception was thrown */
        goto finish;
    }

    if( usageEnum == -1 ) {
        operation = CKA_ENCRYPT; /* doesn't matter, flags will override */
        flags = ALL_SYMKEY_OPS;
    } else {
        operation = JSS_symkeyUsage[usageEnum];
        flags = 0;
    }

    if( temporary ) {
        isPermanent = PR_FALSE;
    } else {
        isPermanent = PR_TRUE;
    }

    if( isPermanent == PR_FALSE) {
        symKey = PK11_UnwrapSymKeyWithFlags(wrappingKey, wrappingMech, param,
            wrappedKey, keyTypeMech, operation, keyLen, flags);

    } else {
        symKey = PK11_UnwrapSymKeyWithFlagsPerm(wrappingKey, wrappingMech, param,
            wrappedKey, keyTypeMech, operation, keyLen, flags,isPermanent);
    }

    if( symKey == NULL ) {
        JSS_throwMsgPrErr(env, TOKEN_EXCEPTION, "Failed to unwrap key");
        goto finish;
    }

    /* wrap the symmetric key in a Java object.  This will clear symKey */
    keyObj = JSS_PK11_wrapSymKey(env, &symKey);

finish:
    if(wrappedKey) {
        SECITEM_FreeItem(wrappedKey, PR_TRUE /*free wrappedKey*/);
    }
    if(iv) {
        SECITEM_FreeItem(iv, PR_TRUE /*free iv*/);
    }
    if(param) {
        SECITEM_FreeItem(param, PR_TRUE /*free param*/);
    }
    if( symKey ) {
        PK11_FreeSymKey(symKey);
    }
    return keyObj;
}

/***********************************************************************
 *
 * PK11KeyWrapper.nativeUnwrapSymWithPriv
 */
JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_pkcs11_PK11KeyWrapper_nativeUnwrapSymWithPriv
    (JNIEnv *env, jclass clazz, jobject tokenObj, jobject unwrapperObj,
        jbyteArray wrappedBA, jobject wrapAlgObj, jobject typeAlgObj,
        jint keyLen, jobject paramsPtr, jlong paramsSize, jint usageEnum)
{
    PK11SymKey *symKey=NULL;
    CK_MECHANISM_TYPE keyTypeMech=0, mech=0;
    SECItem *wrappedKey=NULL;
    jobject keyObj=NULL;
    CK_VOID_PTR params=NULL;
    SECItem paramItem;
    SECItem *paramsItemPtr=NULL;
    SECKEYPrivateKey *wrappingKey=NULL;
    CK_ULONG operation;

    /* get key type */
    keyTypeMech = JSS_getPK11MechFromAlg(env, typeAlgObj);
    if( keyTypeMech == CKM_INVALID_MECHANISM ) {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "Unrecognized key type algorithm");
        goto finish;
    }

    /* get wrapping key */
    if( JSS_PK11_getPrivKeyPtr(env, unwrapperObj, &wrappingKey) != PR_SUCCESS) {
        /* exception was thrown */
        goto finish;
    }

    /* get the mechanism parameter (IV) */
    if (paramsPtr != NULL) {
        if (JSS_PR_getStaticVoidRef(env, paramsPtr, &params) != PR_SUCCESS) {
            JSS_throwMsg(env, TOKEN_EXCEPTION, "Unable to extract parameters "
                "to pass with the wrapping mechanism");
            return NULL;
        }
    }

    /* get the wrapped key */
    wrappedKey = JSS_ByteArrayToSECItem(env, wrappedBA);
    if( wrappedKey == NULL ) {
        /* exception was thrown */
        goto finish;
    }

    if( usageEnum == -1 ) {
        /*
            !!!XXX If they didn't specify a usage, we'll assume decrypt
            because that's the most common case, and we can't specify more
            than one.  See bug 135255.
         */
        operation = CKA_DECRYPT;
    } else {
        operation = JSS_symkeyUsage[usageEnum];
    }

    /* get the mechanism */
    mech = JSS_getPK11MechFromAlg(env, wrapAlgObj);
    if(mech == CKM_INVALID_MECHANISM) {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "Unrecognized algorithm");
        goto finish;
    }

    if (params != NULL && paramsSize != 0) {
        /* Only provision parameters when they're present. Otherwise, leave
         * it as a NULL pointer. */
        paramItem.data = params;
        paramItem.len = paramsSize;
        paramsItemPtr = &paramItem;
    }

#ifdef HAVE_NSS_OAEP
    symKey = PK11_PubUnwrapSymKeyWithMechanism(wrappingKey, mech, paramsItemPtr,
            wrappedKey, keyTypeMech, operation, keyLen);
#else
    if (mech == CKM_RSA_PKCS_OAEP) {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "RSA-OAEP not supported by the NSS version used to build JSS");
        goto finish;
    }

    symKey = PK11_PubUnwrapSymKey(wrappingKey, wrappedKey, keyTypeMech,
                                  operation, keyLen);
#endif

    if( symKey == NULL ) {
        JSS_throwMsgPrErr(env, TOKEN_EXCEPTION, "Failed to unwrap key");
        goto finish;
    }
    
    /* Put the symmetric key into a Java object.  This will clear symKey */
    keyObj = JSS_PK11_wrapSymKey(env, &symKey);

finish:
    if(wrappedKey) {
        SECITEM_FreeItem(wrappedKey, PR_TRUE /*free wrappedKey*/);
    }
    if( symKey ) {
        PK11_FreeSymKey(symKey);
    }
    return keyObj;
}

PK11SymKey *JSS_PK11_ImportSymKeyWithFlagsFIPS(PK11SlotInfo *slot, CK_MECHANISM_TYPE type,
        CK_ATTRIBUTE_TYPE operation, SECItem *key, CK_FLAGS flags,
        PRBool isPerm, void *wincx)
{
    PK11SymKey *result = NULL;
    PK11SymKey *wrapper = NULL;
    SECStatus ret = SECFailure;
    unsigned int wrapped_len = 0;
    unsigned int wrapped_max = key->len + 64;
    unsigned char *wrapped_key = calloc(wrapped_max, sizeof(unsigned char));
    SECItem wrapped_item = { siBuffer, wrapped_key, 0 };
    SECItem *param = NULL;

    /* Steps:
     * 1. Generate a temporary key to encrypt and unwrap with,
     * 2. Encrypt our key to import using the wrapping key,
     * 3. Unwrap into the token using the wrapping key.
     */

#define FIPS_KEYGEN_ALGO CKM_AES_KEY_GEN
#define FIPS_ENCRYPT_UNWRAP_ALGO CKM_AES_KEY_WRAP_PAD

    wrapper = PK11_KeyGen(slot, FIPS_KEYGEN_ALGO, NULL, 32, wincx);
    if (wrapper == NULL) {
        goto done;
    }

    param = PK11_GenerateNewParam(FIPS_ENCRYPT_UNWRAP_ALGO, wrapper);
    if (param == NULL) {
        goto done;
    }

    ret = PK11_Encrypt(wrapper, FIPS_ENCRYPT_UNWRAP_ALGO, param,
            wrapped_key, &wrapped_len, wrapped_max,
            key->data, key->len);
    if (ret != SECSuccess) {
        goto done;
    }

    wrapped_item.len = wrapped_len;

    result = PK11_UnwrapSymKeyWithFlagsPerm(wrapper, FIPS_ENCRYPT_UNWRAP_ALGO,
            param, &wrapped_item, type, operation, key->len, flags,
            isPerm);

done:
    free(wrapped_key);
    SECITEM_FreeItem(param, PR_TRUE);
    if (wrapper != NULL) {
        PK11_DeleteTokenSymKey(wrapper);
        PK11_FreeSymKey(wrapper);
    }
    return result;
}

/***********************************************************************
 *
 * PK11KeyWrapper.nativeUnwrapSymPlaintext
 */
JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_pkcs11_PK11KeyWrapper_nativeUnwrapSymPlaintext
    (JNIEnv *env, jclass clazz, jobject tokenObj, jbyteArray wrappedBA,
        jobject typeAlgObj, jint usageEnum, jboolean temporary)
{
    PK11SymKey *symKey=NULL;
    CK_MECHANISM_TYPE keyTypeMech;
    SECItem *wrappedKey=NULL;
    jobject keyObj = NULL;
    PK11SlotInfo *slot = NULL;
    CK_ULONG operation;
    CK_FLAGS flags;
    PRBool isPerm = PR_FALSE;

    /* get key type */
    keyTypeMech = JSS_getPK11MechFromAlg(env, typeAlgObj);
    if( keyTypeMech == CKM_INVALID_MECHANISM ) {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "Unrecognized key type algorithm");
        goto finish;
    }

    if( temporary ) {
        isPerm = PR_FALSE;
    } else {
        isPerm = PR_TRUE;
    }

    /* get the slot */
    if( JSS_PK11_getTokenSlotPtr(env, tokenObj, &slot) != PR_SUCCESS) {
        /* exception was thrown */
        goto finish;
    }

    /* get the wrapped key */
    wrappedKey = JSS_ByteArrayToSECItem(env, wrappedBA);
    if( wrappedKey == NULL ) {
        /* exception was thrown */
        goto finish;
    }

    if( usageEnum == -1 ) {
        operation = CKA_ENCRYPT;
        flags = ALL_SYMKEY_OPS;
    } else {
        operation = JSS_symkeyUsage[usageEnum];
        flags = 0;
    }

    /* pull in the key */
    if (PK11_IsFIPS()) {
        symKey = JSS_PK11_ImportSymKeyWithFlagsFIPS(slot, keyTypeMech, operation, wrappedKey, flags, isPerm, NULL);
    } else {
        symKey = PK11_ImportSymKeyWithFlags(slot, keyTypeMech, PK11_OriginUnwrap, operation, wrappedKey, flags, isPerm, NULL);
    }
    if( symKey == NULL ) {
        JSS_throwMsgPrErr(env, TOKEN_EXCEPTION, "Failed to unwrap key");
        goto finish;
    }

    /* wrap the symmetric key in a Java object.  This will clear symKey */
    keyObj = JSS_PK11_wrapSymKey(env, &symKey);

finish:
    if(wrappedKey) {
        SECITEM_FreeItem(wrappedKey, PR_TRUE /*free wrappedKey*/);
    }
    if( symKey ) {
        PK11_FreeSymKey(symKey);
    }
    return keyObj;
}


/***********************************************************************
 *
 * J S S _ P K 1 1 _ g e t E r r o r S t r i n g
 *
 * Returns a simple error string for a given PKCS #11 error.
 */
char*
JSS_PK11_getErrorString(CK_RV crv)
{
    switch(crv) {
      case CKR_ATTRIBUTE_READ_ONLY:
        return "CKR_ATTRIBUTE_READ_ONLY";
      case CKR_ATTRIBUTE_TYPE_INVALID:
        return "CKR_ATTRIBUTE_TYPE_INVALID";
      case CKR_ATTRIBUTE_VALUE_INVALID:
        return "CKR_ATTRIBUTE_VALUE_INVALID";
      case CKR_BUFFER_TOO_SMALL:
        return "CKR_BUFFER_TOO_SMALL";
      case CKR_CRYPTOKI_NOT_INITIALIZED:
        return "CKR_CRYPTOKI_NOT_INITIALIZED";
      case CKR_DEVICE_ERROR:
        return "CKR_DEVICE_ERROR";
      case CKR_DEVICE_MEMORY:
        return "CKR_DEVICE_MEMORY";
      case CKR_DEVICE_REMOVED:
        return "CKR_DEVICE_REMOVED";
      case CKR_FUNCTION_CANCELED:
        return "CKR_FUNCTION_CANCELED";
      case CKR_FUNCTION_FAILED:
        return "CKR_FUNCTION_FAILED";
      case CKR_GENERAL_ERROR:
        return "CKR_GENERAL_ERROR";
      case CKR_HOST_MEMORY:
        return "CKR_HOST_MEMORY";
      case CKR_KEY_HANDLE_INVALID:
        return "CKR_KEY_HANDLE_INVALID";
      case CKR_KEY_NOT_WRAPPABLE:
        return "CKR_KEY_NOT_WRAPPABLE";
      case CKR_KEY_SIZE_RANGE:
        return "CKR_KEY_SIZE_RANGE";
      case CKR_KEY_UNEXTRACTABLE:
        return "CKR_KEY_UNEXTRACTABLE";
      case CKR_MECHANISM_INVALID:
        return "CKR_MECHANISM_INVALID";
      case CKR_MECHANISM_PARAM_INVALID:
        return "CKR_MECHANISM_PARAM_INVALID";
      case CKR_OK:
        return "CKR_OK";
      case CKR_OPERATION_ACTIVE:
        return "CKR_OPERATION_ACTIVE";
      case CKR_SESSION_CLOSED:
        return "CKR_SESSION_CLOSED";
      case CKR_SESSION_HANDLE_INVALID:
        return "CKR_SESSION_HANDLE_INVALID";
      case CKR_SESSION_READ_ONLY:
        return "CKR_SESSION_READ_ONLY";
      case CKR_TEMPLATE_INCOMPLETE:
        return "CKR_TEMPLATE_INCOMPLETE";
      case CKR_TEMPLATE_INCONSISTENT:
        return "CKR_TEMPLATE_INCONSISTENT";
      case CKR_TOKEN_WRITE_PROTECTED:
        return "CKR_TOKEN_WRITE_PROTECTED";
      case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
        return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
      case CKR_UNWRAPPING_KEY_SIZE_RANGE:
        return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
      case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
        return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
      case CKR_USER_NOT_LOGGED_IN:
        return "CKR_USER_NOT_LOGGED_IN";
      case CKR_WRAPPED_KEY_INVALID:
        return "CKR_WRAPPED_KEY_INVALID";
      case CKR_WRAPPED_KEY_LEN_RANGE:
        return "CKR_WRAPPED_KEY_LEN_RANGE";
      case CKR_WRAPPING_KEY_HANDLE_INVALID:
        return "CKR_WRAPPING_KEY_HANDLE_INVALID";
      case CKR_WRAPPING_KEY_SIZE_RANGE:
        return "CKR_WRAPPING_KEY_SIZE_RANGE";
      case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
        return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
      default:
        return "PKCS #11 error";
    }
}

/*
 * Get the wrapping mechanism
 */ 
CK_MECHANISM_TYPE getSupportedWrappingMechanism(JNIEnv *env, jobject algObj, PK11SlotInfo *slot)
{
    CK_MECHANISM_TYPE mech = JSS_getPK11MechFromAlg(env, algObj);

    /*
     * Currently, NSS has different definitions for the AES KeyWrap
     * mechanisms from the PKCS11 standard.
     * Below, we first check for support of the PKCS11 standard;
     * If supported, we go with that, if not, we try the NSS ones
     */
    if ( mech == CKM_AES_KEY_WRAP ||
             mech == CKM_NSS_AES_KEY_WRAP) {
        if (!PK11_DoesMechanism(slot, CKM_AES_KEY_WRAP)) {
            mech = CKM_NSS_AES_KEY_WRAP;
        } else {
            mech = CKM_AES_KEY_WRAP;
        }
    } else if ( mech == CKM_AES_KEY_WRAP_PAD
            || mech == CKM_NSS_AES_KEY_WRAP_PAD) {
        if (!PK11_DoesMechanism(slot, CKM_AES_KEY_WRAP_PAD)) {
            mech = CKM_NSS_AES_KEY_WRAP_PAD;
        } else {
            mech = CKM_AES_KEY_WRAP_PAD;
        }
    }
    return mech;
}
