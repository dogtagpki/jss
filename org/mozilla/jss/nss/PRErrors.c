#include <nspr.h>
#include <limits.h>
#include <stdint.h>
#include <jni.h>

#include "jssutil.h"
#include "PRFDProxy.h"
#include "BufferProxy.h"
#include "BufferPRFD.h"

#include "_jni/org_mozilla_jss_nss_PRErrors.h"

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_PRErrors_getWouldBlockError(JNIEnv *env, jclass clazz)
{
    return PR_WOULD_BLOCK_ERROR;
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_PRErrors_getSocketShutdownError(JNIEnv *env, jclass clazz)
{
    return PR_SOCKET_SHUTDOWN_ERROR;
}
