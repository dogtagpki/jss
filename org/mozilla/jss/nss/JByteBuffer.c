#include <nspr.h>
#include <limits.h>
#include <stdint.h>
#include <jni.h>

#include "jssutil.h"
#include "ByteBufferProxy.h"
#include "j_bytebuffer.h"

#include "_jni/org_mozilla_jss_nss_JByteBuffer.h"

JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_nss_JByteBuffer_Create(JNIEnv *env, jclass clazz,
    jboolean writable)
{
    j_bytebuffer *buf = NULL;

    PR_ASSERT(env != NULL);

    buf = jbb_alloc(writable == JNI_TRUE);

    PR_ASSERT(buf != NULL);

    return JSS_PR_wrapJByteBuffer(env, &buf);
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_JByteBuffer_ClearBufferNative(JNIEnv *env,
    jclass clazz, jobject proxy, jbyteArray last)
{
    j_bytebuffer *buf = NULL;

    PR_ASSERT(env != NULL && proxy != NULL);

    if (JSS_PR_unwrapJByteBuffer(env, proxy, &buf) != PR_SUCCESS) {
        return 0;
    }

    return jbb_clear_buffer(buf, env, last);
}

JNIEXPORT jboolean JNICALL
Java_org_mozilla_jss_nss_JByteBuffer_SetBufferNative(JNIEnv *env,
    jclass clazz, jobject proxy, jbyteArray array, jlong offset,
    jlong limit)
{
    j_bytebuffer *buf = NULL;

    PR_ASSERT(env != NULL && proxy != NULL);

    if (JSS_PR_unwrapJByteBuffer(env, proxy, &buf) != PR_SUCCESS ||
            buf == NULL) {
        return JNI_FALSE;
    }

    return jbb_set_buffer(buf, env, array, offset, limit);
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_JByteBuffer_Capacity(JNIEnv *env,
    jclass clazz, jobject proxy)
{
    j_bytebuffer *buf = NULL;

    PR_ASSERT(env != NULL && proxy != NULL);

    if (JSS_PR_unwrapJByteBuffer(env, proxy, &buf) != PR_SUCCESS) {
        return 0;
    }

    return jbb_capacity(buf);
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_nss_JByteBuffer_FreeNative(JNIEnv *env, jclass clazz,
    jobject proxy)
{
    j_bytebuffer *buf = NULL;

    PR_ASSERT(env != NULL && proxy != NULL);

    if (JSS_PR_unwrapJByteBuffer(env, proxy, &buf) != PR_SUCCESS ||
            buf == NULL) {
        return;
    }

    jbb_free(buf, env);
    JSS_clearPtrFromProxy(env, proxy);
}
