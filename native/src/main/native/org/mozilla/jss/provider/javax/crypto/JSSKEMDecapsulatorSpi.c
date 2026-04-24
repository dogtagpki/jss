//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
#include "_jni/org_mozilla_jss_provider_javax_crypto_JSSKEMDecapsulatorSpi.h"
#include <jssutil.h>
#include <jss_exceptions.h>
#include <pk11util.h>
#include "../../../ssl/jssl.h"

/*
 * Class:     org_mozilla_jss_provider_javax_crypto_JSSKEMDecapsulatorSpi
 * Method:    engineDecapsulateNative
 */
JNIEXPORT jobject JNICALL Java_org_mozilla_jss_provider_javax_crypto_JSSKEMDecapsulatorSpi_engineDecapsulateNative
(JNIEnv *env, jobject self, jobject privateKey, jbyteArray encapsulation, jint size, jlong target) {
  SECKEYPrivateKey *privKey = NULL;
  CK_MECHANISM_TYPE mechTarget = (CK_MECHANISM_TYPE)target;
  PK11SymKey *symKey = NULL;
  PK11SymKey *tmpSymKey = NULL;
  SECItem *ciphertext = NULL;
  SECStatus rv = SECFailure;
  jobject jSymKey = NULL;
  
  // 1. Extract native SECKEYPrivateKey from Java PrivateKey object
  if (JSS_PK11_getPrivKeyPtr(env, privateKey, &privKey) != PR_SUCCESS) {
    PR_ASSERT((*env)->ExceptionOccurred(env) != NULL);
    goto finish;
  }

  // 2. Convert encapsulation to ciphertext
  ciphertext = JSS_ByteArrayToSECItem(env, encapsulation);
  if (ciphertext == NULL) {
    goto finish;
  }    
  
  // 3. Call NSS PK11_Decapsulate
  if (mechTarget == CKM_AES_CBC ||
      mechTarget == CKM_AES_ECB ||
      mechTarget == CKM_AES_GCM) {
    rv = PK11_Decapsulate(privKey, ciphertext,
                          CKM_HKDF_DERIVE,
                          PK11_ATTR_SESSION,
                          CKF_DERIVE, &tmpSymKey);

    if (rv != SECSuccess) {
      JSS_throwMsgPrErr(env, TOKEN_EXCEPTION, "PK11_Decapsulate failed");
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
    rv = PK11_Decapsulate(privKey, ciphertext, mechTarget,
                          PK11_ATTR_SESSION, CKF_DERIVE,
                          &symKey);
    if (rv != SECSuccess) {
      JSS_throwMsgPrErr(env, TOKEN_EXCEPTION, "PK11_Decapsulate failed");
      goto finish;
    }
  }


  // 4. Wrap the PK11SymKey* into a Java PK11SymKey object
  jSymKey = JSS_PK11_wrapSymKey(env, &symKey);
  if (jSymKey == NULL) {
    goto finish;
  }


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

  return jSymKey;
}
