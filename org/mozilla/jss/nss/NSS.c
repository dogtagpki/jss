#include <nss.h>
#include <limits.h>
#include <stdint.h>
#include <jni.h>

#include "_jni/org_mozilla_jss_nss_NSS.h"

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_NSS_Init(JNIEnv *env, jclass clazz, jstring directory)
{
    SECStatus status;
    char *nssdb_path;

    PR_ASSERT(env != NULL && directory != NULL);

    nssdb_path = (char *)(*env)->GetStringUTFChars(env, directory, NULL);
    if (nssdb_path == NULL) {
         return 1;
    }

    status = NSS_Init(nssdb_path);
    return status;
}
