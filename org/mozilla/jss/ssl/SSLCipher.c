#include <nspr.h>
#include <nss.h>
#include <ssl.h>
#include <pk11pub.h>
#include <jni.h>

#include "_jni/org_mozilla_jss_ssl_SSLCipher.h"

JNIEXPORT jboolean JNICALL
Java_org_mozilla_jss_ssl_SSLCipher_checkSupportedStatus(JNIEnv *env, jclass clazz, jint cipher_suite)
{
    SSLCipherSuiteInfo info = { 0 };
    jboolean found = JNI_FALSE;

    for (PRUint16 index = 0; index < SSL_NumImplementedCiphers; index++) {
        if (SSL_ImplementedCiphers[index] == cipher_suite) {
            found = JNI_TRUE;
            break;
        }
    }

    if (found == JNI_FALSE) {
        return found;
    }

    if (SSL_GetCipherSuiteInfo(cipher_suite, &info, sizeof(info)) != SECSuccess || info.length < sizeof(info)) {
        return JNI_FALSE;
    }

    if (info.nonStandard != 0) {
        return JNI_FALSE;
    }

    if (info.isFIPS == 0 && PK11_IsFIPS()) {
        return JNI_FALSE;
    }

    return JNI_TRUE;
}
