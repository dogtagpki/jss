/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "_jni/org_mozilla_jss_pkcs11_PK11SymmetricKeyDeriver.h"
#include <plarena.h>
#include <secmodt.h>
#include <pk11func.h>
#include <pk11pqg.h>
#include <secerr.h>
#include <nspr.h>
#include <key.h>
#include <secasn1.h>
#include <base64.h>
#include <cert.h>
#include <cryptohi.h>

#include <jssutil.h>
#include <jss_exceptions.h>
#include <jss_bigint.h>
#include <Algorithm.h>
#include <jni.h>
#include <secitem.h>
#include "java_ids.h"

#include "pk11util.h"
#include <plstr.h>

/***********************************************************************
 * Expose the NSS functionality at low level, one should know what to do
 * at the Java level. 
 */

JNIEXPORT jobject JNICALL Java_org_mozilla_jss_pkcs11_PK11SymmetricKeyDeriver_nativeDeriveSymKey
  (JNIEnv * env, jobject this,jobject tokenObj, 
  jobject baseKeyObj, jobject secondaryKeyObj, 
  jlong deriveMechanism, jbyteArray param, jbyteArray iv, jlong targetMechanism, jlong operation, jlong keySize)
{
    jobject keyObj = NULL;
    PK11SlotInfo *slot=NULL;
    PK11SlotInfo *bestSlot = NULL;
    PK11SlotInfo *slotForKey = NULL;
    PK11SlotInfo *slotForSecondaryKey = NULL;
    PK11SlotInfo *finalSlot = NULL;
    PK11SlotInfo *finalSecondarySlot = NULL;
    PK11SlotInfo *finalBaseKeySlot = NULL;

    PK11SymKey *baseKey = NULL;
    PK11SymKey *bestBaseKey = NULL;
    PK11SymKey *finalBaseKey = NULL;
    PK11SymKey *newKey = NULL;

    PK11SymKey *secondaryKey = NULL;
    PK11SymKey *bestSecondaryKey = NULL;
    PK11SymKey *finalSecondaryKey = NULL;
    PK11SymKey *derivedKey = NULL;
    jbyte *paramValue = NULL;
    int paramLength = 0;
    jbyte *ivValue = NULL;
    int ivLength = 0;


    CK_OBJECT_HANDLE keyhandle = 0;

    CK_AES_CBC_ENCRYPT_DATA_PARAMS aes;
    CK_DES_CBC_ENCRYPT_DATA_PARAMS des;
    CK_KEY_DERIVATION_STRING_DATA string;

    SECItem paramsItem = { siBuffer, NULL, 0 };

    PR_ASSERT(env!=NULL && this!=NULL);

    if( baseKeyObj == 0) {
        PR_fprintf(PR_STDOUT,"baseKeyObj can not be null!\n");
        goto loser;
    }

    if( param != NULL) {
        paramValue = (*env)->GetByteArrayElements(env,param, NULL);
        paramLength = (*env)->GetArrayLength(env,param);
    }

    if( iv != NULL) {
        ivValue = (*env)->GetByteArrayElements(env,iv, NULL);
        ivLength = (*env)->GetArrayLength(env,iv);
    }

    /* Set up the params data for the PK11_Derive family */

    switch ( deriveMechanism ) {
        case CKM_DES_ECB_ENCRYPT_DATA:
        case CKM_DES3_ECB_ENCRYPT_DATA:
        case CKM_AES_ECB_ENCRYPT_DATA:
        case CKM_CAMELLIA_ECB_ENCRYPT_DATA:
        case CKM_SEED_ECB_ENCRYPT_DATA:
        /* Use CK_KEY_DERIVATION_STRING_DATA */ 

            string.pData = (unsigned char *) paramValue;
            string.ulLen = paramLength;
            paramsItem.data = (void *) &string;
            paramsItem.len = sizeof(string);

        break;
        case CKM_DES_CBC_ENCRYPT_DATA:
        case CKM_DES3_CBC_ENCRYPT_DATA:
        /* Use CK_DES_CBC_ENCRYPT_DATA_PARAMS */
    
            if( ivValue == NULL) {
               PR_fprintf(PR_STDOUT, "Need iv param for CKM_DES_CBC_ENCRYPT_DATA or CKM_DES3_CBC_ENCRYPT_DATA. \n");
               goto loser;
            }

             if( ivLength != 8) {
               PR_fprintf(PR_STDOUT, "Need iv param for CKM_DES_CBC_ENCRYPT_DATA  structure to be 8 bytes!. \n");
               goto loser;
            }

            des.pData = (unsigned char *) paramValue;
            des.length = paramLength;
            PORT_Memcpy(des.iv,ivValue,ivLength);
            paramsItem.data = (void *) &des;
            paramsItem.len = sizeof(des);
    
        break;

        case CKM_AES_CBC_ENCRYPT_DATA:
        case CKM_CAMELLIA_CBC_ENCRYPT_DATA:
        case CKM_SEED_CBC_ENCRYPT_DATA:
        /* Use CK_AES_CBC_ENCRYPT_DATA_PARAMS */
            
            if ( ivValue == NULL ) {
                PR_fprintf(PR_STDOUT, "Need iv param for CBC encrypt derive for AES, or CAMELLIA or SEED. \n");
                goto loser;
            }

            if( ivLength != 16) {
                PR_fprintf(PR_STDOUT, "Need iv param for CK_AES_CBC_ENCRYPT_DATA_PARAMS structure to be 16 bytes!. \n");
                goto loser;
            }

            aes.pData = (unsigned char *) paramValue;
            aes.length = paramLength;
            PORT_Memcpy(aes.iv,ivValue,ivLength);
            paramsItem.data = (void *) &aes;
            paramsItem.len = sizeof(aes);
        break;
        default:
            paramsItem.data = (unsigned char *) paramValue;
            paramsItem.len = paramLength;
        break;
    }

    /* Get slot */
    if( JSS_PK11_getTokenSlotPtr(env, tokenObj, &slot) != PR_SUCCESS) {
        goto loser;
    }

    /* Get base key */

    if( JSS_PK11_getSymKeyPtr(env, baseKeyObj, &baseKey) != PR_SUCCESS) {
        PR_fprintf(PR_STDOUT, "PK11SymmetricKeyDeriver.nativeDeriveSymKey: Unable to extract symmetric base key!");
        goto loser;
    }

    /* Ask NSS what the best slot for the given mechanism */

    bestSlot = PK11_GetBestSlot(deriveMechanism, NULL);

    if( bestSlot == NULL) {
        PR_fprintf(PR_STDOUT,"PK11SymmetricKeyDeriver.nativeDeriveSymKey: Can't find suitable slot for sym key derivation! \n");
        goto loser;
    }

    slotForKey = PK11_GetSlotFromKey(baseKey);

    int keyOnRequestedSlot = 0;

    if(slotForKey != slot) {
        keyOnRequestedSlot = 0;
    }  else {
        keyOnRequestedSlot = 1;
        finalBaseKeySlot = slot;
    } 

    if ( PK11_DoesMechanism( slot, deriveMechanism)) {
        if ( keyOnRequestedSlot ) {
            finalBaseKey = baseKey;
        } else {
            bestBaseKey = PK11_MoveSymKey( slot, CKA_ENCRYPT, 0, PR_FALSE, baseKey );
            if(bestBaseKey == NULL) {
                PR_fprintf(PR_STDOUT,"PK11SymmetricKeyDeriver.nativeDeriveSymKey:  Can't move Base Key to requested slot!\n");
                goto loser;
            }
            finalBaseKey = bestBaseKey;
            finalBaseKeySlot = slot;
        }

    } else {
            bestBaseKey = PK11_MoveSymKey( bestSlot, CKA_ENCRYPT, 0, PR_FALSE, baseKey );
            if(bestBaseKey == NULL) {
                PR_fprintf(PR_STDOUT,"PK11SymmetricKeyDeriver.nativeDeriveSymKey:  Can't move Base Key to best slot!\n");
                goto loser;
            }
            finalBaseKey = bestBaseKey;
            finalBaseKeySlot = bestSlot;
    }

    /* Assume we want to do a concatenation family here */

    if( secondaryKeyObj != NULL) {
        if( JSS_PK11_getSymKeyPtr(env, secondaryKeyObj, &secondaryKey) != PR_SUCCESS) {
            PR_fprintf(PR_STDOUT,"PK11SymmetricKeyDeriver.nativeDeriveSymKey:  Can't find secondary sym key!\n");
            goto loser;
        }

        /* Make sure the secondary key is in the proper slot to do concatenation */

        slotForSecondaryKey = PK11_GetSlotFromKey( secondaryKey );

        if( finalBaseKeySlot != slotForSecondaryKey ) {

            finalSecondaryKey = PK11_MoveSymKey (finalBaseKeySlot, CKA_ENCRYPT, 0, PR_FALSE, secondaryKey);

            if( finalSecondaryKey == NULL) {
                PR_fprintf(PR_STDOUT,"PK11SymmetricKeyDeriver.nativeDeriveSymKey, Problem moving secondary key to proper slot.\n");
                goto loser;
            }
        } else {
            finalSecondaryKey = secondaryKey;
        }

        if( paramValue == NULL) {
            keyhandle = PK11_GetSymKeyHandle(finalSecondaryKey);

            if( keyhandle == 0) {
                PR_fprintf(PR_STDOUT,"PK11SymmetricKeyDeriver.nativeDeriveSymKey, can't get handle for secondary sym key.\n");
                goto loser;
            }

            paramsItem.data=(unsigned char *) &keyhandle;
            paramsItem.len=sizeof(keyhandle);

        } else {
            PR_fprintf(PR_STDOUT,"PK11SymmetricKeyDeriver.nativeDeriveSymKey: incorrect input parameter provided!\n");
            goto loser;
        }
    }

    derivedKey = PK11_Derive(finalBaseKey, deriveMechanism, &paramsItem, targetMechanism,
                                                            operation, keySize);
    if(derivedKey == NULL) {
        PR_fprintf(PR_STDOUT,
                    "ERROR: Can't derive symmetric key, error: %d \n",PR_GetError());
        goto loser;
    }

    if ( (finalSlot =  PK11_GetSlotFromKey(derivedKey )) != slot) {
        newKey =  PK11_MoveSymKey ( slot, CKA_ENCRYPT, 0, PR_FALSE, derivedKey);

        if ( newKey == NULL ) {
            PR_fprintf(PR_STDOUT,"PK11SymmetricKeyDeriver.nativeDeriveSymKey: error moving key to original slot, return anyway. \n");
            newKey = derivedKey;
            derivedKey = NULL;
        }
       
    }  else {
        newKey = derivedKey;
        derivedKey = NULL;
    }

    keyObj = JSS_PK11_wrapSymKey(env, &newKey);

loser:

    if ( bestBaseKey != NULL ) {
       PK11_FreeSymKey ( bestBaseKey );
       bestBaseKey = NULL;
    }

    if ( bestSecondaryKey != NULL ) {
       PK11_FreeSymKey ( bestSecondaryKey );
       bestSecondaryKey = NULL;
    }

    if ( derivedKey != NULL) {
      PK11_FreeSymKey ( derivedKey );
      derivedKey = NULL;
    }

    if (bestSlot != NULL ) {
       PK11_FreeSlot(bestSlot);
       bestSlot = NULL;
    }

    if ( slotForKey != NULL ) {
       PK11_FreeSlot( slotForKey );
       slotForKey = NULL;
    }

    if ( finalSlot != NULL ) {
       PK11_FreeSlot( finalSlot );
       finalSlot = NULL;
    }

    if ( finalSecondarySlot != NULL ) {
       PK11_FreeSlot( finalSecondarySlot );
       finalSecondarySlot = NULL;
    }

    if ( slotForSecondaryKey != NULL ) {
       PK11_FreeSlot( slotForSecondaryKey );
       slotForSecondaryKey = NULL;
    }

    if(paramValue) {
        (*env)->ReleaseByteArrayElements(env, param, (jbyte*)paramValue,
                                                              JNI_ABORT);
    }
    if(ivValue) {
        (*env)->ReleaseByteArrayElements(env, iv, (jbyte*)ivValue,
                                                        JNI_ABORT);
    }

    if( keyObj == NULL) {
        JSS_throwMsgPrErr(env, TOKEN_EXCEPTION, "Unable to derive symmetric key! "
                 "failure!");
    }

    return keyObj; 
}
