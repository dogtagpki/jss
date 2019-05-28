#include <jni.h>
#include <nspr.h>
#include <ssl.h>

#include "SSLVersionRange.h"
#include "java_ids.h"
#include "jssl.h"

jobject JSS_SSL_wrapVersionRange(JNIEnv *env, SSLVersionRange vrange)
{
    jobject versionRange = NULL;
    jclass versionRangeClass = NULL;
    jmethodID versionRangeCons = NULL;

    /*
     * Package the status into a new SSLVersionRange object.
     */
    versionRangeClass = (*env)->FindClass(env, SSL_VERSION_RANGE_CLASS_NAME);
    PR_ASSERT(versionRangeClass != NULL);
    if (versionRangeClass == NULL) {
        /* exception was thrown */
        goto finish;
    }

    /*
     * Get a reference to the constructor so we can call it.
     */
    versionRangeCons = (*env)->GetMethodID(env, versionRangeClass,
                                           SSL_VERSION_RANGE_CONSTRUCTOR_NAME,
                                           SSL_VERSION_RANGE_CONSTRUCTOR_SIG);
    PR_ASSERT(versionRangeCons != NULL);
    if (versionRangeCons == NULL) {
        /* exception was thrown */
        goto finish;
    }

    /*
     * Try constructing the new object; returns NULL when construction fails.
    */
    versionRange = (*env)->NewObject(env, versionRangeClass, versionRangeCons,
                                     JSSL_enums_reverse(vrange.min),
                                     JSSL_enums_reverse(vrange.max));

finish:
    return versionRange;
}
