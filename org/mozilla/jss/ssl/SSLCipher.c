#include <nspr.h>
#include <nss.h>
#include <ssl.h>
#include <jni.h>
#include <pk11pub.h>

#include "_jni/org_mozilla_jss_ssl_SSLCipher.h"

JNIEXPORT jboolean JNICALL
Java_org_mozilla_jss_ssl_SSLCipher_checkSupportedStatus(JNIEnv *env, jclass clazz, jint cipher_suite)
{
    PRInt32 allowed;

    if (SSL_CipherPolicyGet(cipher_suite, &allowed) != SECSuccess) {
        return JNI_FALSE;
    }

    if (!PK11_IsFIPS() || allowed != SSL_ALLOWED) {
        return (allowed == SSL_ALLOWED) ? JNI_TRUE : JNI_FALSE;
    }

    /* Our NSS DB or application could've configured FIPS mode explicitly,
     * even though the system might not be in FIPS mode. In that case,
     * explicitly check that this allowed cipher is available in FIPS mode. */
    SSLCipherSuiteInfo info = { 0 };
    if (SSL_GetCipherSuiteInfo(cipher_suite, &info, sizeof(info)) != SECSuccess || info.length < sizeof(info)) {
        return JNI_FALSE;
    }

    return (info.isFIPS != 0) ? JNI_TRUE : JNI_FALSE;
}
