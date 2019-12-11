#include "_jni/org_mozilla_jss_crypto_Policy.h"

#include <nspr.h>
#include <nss.h>
#include <jni.h>

jint
nearest_power_of_two(jint value)
{
    for (jint exponent = 8; exponent < 20; exponent++) {
        if ((1 << exponent) >= value) {
            return 1 << exponent;
        }
    }

    return value;
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_crypto_Policy_getRSAMinimumKeySize(JNIEnv *env, jclass clazz)
{
    PRInt32 value = 0;
    SECStatus ret = NSS_OptionGet(NSS_RSA_MIN_KEY_SIZE, &value);
    if (ret != SECSuccess) {
        PR_ASSERT(PR_FALSE);
    }

    return nearest_power_of_two(value);
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_crypto_Policy_getDHMinimumKeySize(JNIEnv *env, jclass clazz)
{
    PRInt32 value = 0;
    SECStatus ret = NSS_OptionGet(NSS_DH_MIN_KEY_SIZE, &value);
    if (ret != SECSuccess) {
        PR_ASSERT(PR_FALSE);
    }

    return nearest_power_of_two(value);
}


JNIEXPORT jint JNICALL
Java_org_mozilla_jss_crypto_Policy_getDSAMinimumKeySize(JNIEnv *env, jclass clazz)
{
    PRInt32 value = 0;
    SECStatus ret = NSS_OptionGet(NSS_DSA_MIN_KEY_SIZE, &value);
    if (ret != SECSuccess) {
        PR_ASSERT(PR_FALSE);
    }

    return nearest_power_of_two(value);
}
