/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "_jni/org_mozilla_jss_crypto_SecretDecoderRing.h"
#include <nspr.h>
#include <secitem.h>
#include <pk11sdr.h>
#include <jss_exceptions.h>
#include <jssutil.h>

typedef enum {SDR_ENCRYPT, SDR_DECRYPT} SDROp;

static jbyteArray
doSDR(JNIEnv *env, jobject this, jbyteArray inputBA, SDROp optype)
{
    SECStatus status;
    jbyteArray outputBA = NULL;
    SECItem keyID = {siBuffer, NULL, 0};
    SECItem *input= NULL;
    SECItem output = {siBuffer, NULL, 0};

    /* convert input to SECItem */
    if( inputBA == NULL ) {
        JSS_throw(env, NULL_POINTER_EXCEPTION);
        goto finish;
    }
    input = JSS_ByteArrayToSECItem(env, inputBA);
    if( input == NULL) {
        /* exception was thrown */
        goto finish;
    }

    /* perform the operation*/
    if( optype == SDR_ENCRYPT ) {
        status = PK11SDR_Encrypt(&keyID, input, &output, NULL /*cx*/);
    } else {
        PR_ASSERT( optype == SDR_DECRYPT);
        status = PK11SDR_Decrypt(input, &output, NULL /*cx*/);
    }
    if(status != SECSuccess) {
        JSS_throwMsg(env, TOKEN_EXCEPTION, "Operation failed");
        goto finish;
    }

    /* convert output to byte array */
    outputBA = JSS_SECItemToByteArray(env, &output);

finish:
    if( input != NULL) {
        SECITEM_FreeItem(input, PR_TRUE /* freeit */);
    }
    SECITEM_FreeItem(&output, PR_FALSE /*freeit*/);
    return outputBA;
}

JNIEXPORT jbyteArray JNICALL
Java_org_mozilla_jss_crypto_SecretDecoderRing_encrypt(
    JNIEnv *env, jobject this, jbyteArray plaintextBA)
{
    return doSDR(env, this, plaintextBA, SDR_ENCRYPT);
}

JNIEXPORT jbyteArray JNICALL
Java_org_mozilla_jss_crypto_SecretDecoderRing_decrypt(
    JNIEnv *env, jobject this, jbyteArray ciphertextBA)
{
    return doSDR(env, this, ciphertextBA, SDR_DECRYPT);
}
