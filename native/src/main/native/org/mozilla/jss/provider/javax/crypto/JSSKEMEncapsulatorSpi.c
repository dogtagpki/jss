//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
#include "_jni/org_mozilla_jss_provider_javax_crypto_JSSKEMEncapsulatorSpi.h"
#include <jssutil.h>
#include <jss_exceptions.h>
#include <pk11util.h>
#include "../../../ssl/jssl.h"

/*
 * Class:     org_mozilla_jss_provider_javax_crypto_JSSKEMEncapsulatorSpi
 * Method:    engineEncapsulateNative
 */
JNIEXPORT jobject JNICALL Java_org_mozilla_jss_provider_javax_crypto_JSSKEMEncapsulatorSpi_engineEncapsulateNative
    (JNIEnv *env, jobject self, jobject publicKey, jint size, jlong target) {
  SECKEYPublicKey *pubKey = NULL;
  CK_MECHANISM_TYPE mechTarget = (CK_MECHANISM_TYPE)target;
  PK11SymKey *symKey = NULL;
  PK11SymKey *tmpSymKey = NULL;
  SECItem *ciphertext = NULL;
  SECStatus rv = SECFailure;
  jobject jSymKey = NULL;
  jbyteArray jCiphertext = NULL;
  jobject encapsulated = NULL;
  jclass encapsulatedClass = NULL;
  jmethodID constructor = NULL;
  
  // 1. Extract native SECKEYPublicKey from Java PublicKey object
  if (JSS_PK11_getPubKeyPtr(env, publicKey, &pubKey) != PR_SUCCESS) {
    PR_ASSERT((*env)->ExceptionOccurred(env) != NULL);
    goto finish;
  }

  // 2. Call NSS PK11_Encapsulate
  if (mechTarget == CKM_AES_CBC ||
      mechTarget == CKM_AES_ECB ||
      mechTarget == CKM_AES_GCM) {
    rv = PK11_Encapsulate(pubKey, CKM_HKDF_DERIVE,
                          PK11_ATTR_SESSION,
                          CKF_DERIVE, &tmpSymKey, &ciphertext);

    if (rv != SECSuccess) {
      JSS_throwMsgPrErr(env, TOKEN_EXCEPTION, "PK11_Encapsulate failed");
      goto finish;
    }
    
    CK_HKDF_PARAMS params = {0};
    params.bExtract = CK_FALSE;
    params.bExpand = CK_TRUE;
    params.prfHashMechanism = CKM_SHA256;
    params.ulSaltType = CKF_HKDF_SALT_NULL;
    SECItem paramsItem = { siBuffer, (unsigned char *)&params, sizeof(params) };
    symKey = PK11_Derive(tmpSymKey, CKM_HKDF_DERIVE, &paramsItem, mechTarget,
                    CKA_ENCRYPT | CKA_DECRYPT | CKA_WRAP | CKA_UNWRAP, size);
    if (symKey == NULL) {
      JSS_throwMsg(env, TOKEN_EXCEPTION,
                   "Failed to create derived symmetric key object");
      goto finish;
    }
  }
  else {
    rv = PK11_Encapsulate(pubKey, mechTarget, PK11_ATTR_SESSION, CKF_DERIVE,
                          &symKey, &ciphertext);
    if (rv != SECSuccess) {
      JSS_throwMsgPrErr(env, TOKEN_EXCEPTION, "PK11_Encapsulate failed");
      goto finish;
    }
  }


  // 3. Wrap the PK11SymKey* into a Java PK11SymKey object
  jSymKey = JSS_PK11_wrapSymKey(env, &symKey);
  if (jSymKey == NULL) {
    goto finish;
  }

  // 4. Convert SECItem ciphertext to Java byte array
  jCiphertext = JSS_SECItemToByteArray(env, ciphertext);
  if (jCiphertext == NULL) {                                                                                    
    goto finish;
  }

  // 5. Create KEM.Encapsulated object

  encapsulatedClass = (*env)->FindClass(env, "javax/crypto/KEM$Encapsulated");
  if (encapsulatedClass == NULL) {
    ASSERT_OUTOFMEM(env);
    goto finish;
  }

  constructor = (*env)->GetMethodID(env, encapsulatedClass, "<init>",
                                    "(Ljavax/crypto/SecretKey;[B[B)V");

  if (constructor == NULL) {
    ASSERT_OUTOFMEM(env);
    goto finish;
  }

  encapsulated = (*env)->NewObject(env, encapsulatedClass, constructor, jSymKey,
                                   jCiphertext, NULL);

finish:
  if (ciphertext != NULL) {
    SECITEM_FreeItem(ciphertext, PR_TRUE);
  }

  if (tmpSymKey != NULL) {
    PK11_FreeSymKey(tmpSymKey);
  }

  if (symKey != NULL) {
    PK11_FreeSymKey(symKey);
  }

  return encapsulated;
}
