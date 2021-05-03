#include <nspr.h>
#include <limits.h>
#include <stdint.h>
#include <jni.h>

#include "jssutil.h"
#include "BufferProxy.h"
#include "j_buffer.h"

#include "_jni/org_mozilla_jss_nss_Buffer.h"

JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_nss_Buffer_Create(JNIEnv *env, jclass clazz, jlong length)
{
    j_buffer *buf = NULL;

    PR_ASSERT(env != NULL && length > 0);

    buf = jb_alloc((size_t) length);
    PR_ASSERT(buf != NULL);

    return JSS_PR_wrapJBuffer(env, &buf);
}

JNIEXPORT jlong JNICALL
Java_org_mozilla_jss_nss_Buffer_Capacity(JNIEnv *env, jclass clazz, jobject buf)
{
    j_buffer *real_buf = NULL;

    PR_ASSERT(env != NULL && buf != NULL);

    if (JSS_PR_unwrapJBuffer(env, buf, &real_buf) != PR_SUCCESS) {
        return 0;
    }

    return jb_capacity(real_buf);
}

JNIEXPORT jboolean JNICALL
Java_org_mozilla_jss_nss_Buffer_CanRead(JNIEnv *env, jclass clazz, jobject buf)
{
    j_buffer *real_buf = NULL;

    PR_ASSERT(env != NULL && buf != NULL);

    if (JSS_PR_unwrapJBuffer(env, buf, &real_buf) != PR_SUCCESS) {
        return false;
    }

    return jb_can_read(real_buf);
}

JNIEXPORT jlong JNICALL
Java_org_mozilla_jss_nss_Buffer_ReadCapacity(JNIEnv *env, jclass clazz, jobject buf)
{
    j_buffer *real_buf = NULL;

    PR_ASSERT(env != NULL && buf != NULL);

    if (JSS_PR_unwrapJBuffer(env, buf, &real_buf) != PR_SUCCESS) {
        return 0;
    }

    return jb_read_capacity(real_buf);
}

JNIEXPORT jboolean JNICALL
Java_org_mozilla_jss_nss_Buffer_CanWrite(JNIEnv *env, jclass clazz, jobject buf)
{
    j_buffer *real_buf = NULL;

    PR_ASSERT(env != NULL && buf != NULL);

    if (JSS_PR_unwrapJBuffer(env, buf, &real_buf) != PR_SUCCESS) {
        return false;
    }

    return jb_can_write(real_buf);
}

JNIEXPORT jlong JNICALL
Java_org_mozilla_jss_nss_Buffer_WriteCapacity(JNIEnv *env, jclass clazz, jobject buf)
{
    j_buffer *real_buf = NULL;

    PR_ASSERT(env != NULL && buf != NULL);

    if (JSS_PR_unwrapJBuffer(env, buf, &real_buf) != PR_SUCCESS) {
        return 0;
    }

    return jb_write_capacity(real_buf);
}

JNIEXPORT jbyteArray JNICALL
Java_org_mozilla_jss_nss_Buffer_Read(JNIEnv *env, jclass clazz, jobject buf,
    jlong length)
{
    j_buffer *real_buf = NULL;
    size_t read_amount = 0;
    uint8_t *tmp = NULL;
    jbyteArray result = NULL;

    PR_ASSERT(env != NULL && buf != NULL && length > 0);

    if (JSS_PR_unwrapJBuffer(env, buf, &real_buf) != PR_SUCCESS) {
        return NULL;
    }

    tmp = calloc(length, sizeof(uint8_t));
    read_amount = jb_read(real_buf, tmp, (size_t) length);
    result = JSS_ToByteArray(env, tmp, read_amount);
    free(tmp);

    return result;
}

JNIEXPORT jlong JNICALL
Java_org_mozilla_jss_nss_Buffer_Write(JNIEnv *env, jclass clazz, jobject buf, jbyteArray input)
{
    j_buffer *real_buf = NULL;
    size_t input_length = 0;
    uint8_t *real_input = NULL;
    long write_amount = -1;

    PR_ASSERT(env != NULL && buf != NULL);

    if (JSS_PR_unwrapJBuffer(env, buf, &real_buf) != PR_SUCCESS) {
        return write_amount;
    }

    if (!JSS_FromByteArray(env, input, &real_input, &input_length)) {
        return write_amount;
    }

    write_amount = jb_write(real_buf, real_input, input_length);
    free(real_input);

    return write_amount;
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_Buffer_Get(JNIEnv *env, jclass clazz, jobject buf)
{
    j_buffer *real_buf = NULL;

    PR_ASSERT(env != NULL && buf != NULL);

    if (JSS_PR_unwrapJBuffer(env, buf, &real_buf) != PR_SUCCESS) {
        return -1;
    }

    return jb_get(real_buf);
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_Buffer_Put(JNIEnv *env, jclass clazz, jobject buf, jbyte input)
{
    j_buffer *real_buf = NULL;

    PR_ASSERT(env != NULL && buf != NULL);

    if (JSS_PR_unwrapJBuffer(env, buf, &real_buf) != PR_SUCCESS) {
        return -1;
    }

    return jb_put(real_buf, (uint8_t) input);
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_nss_Buffer_Free(JNIEnv *env, jclass clazz, jobject buf)
{
    j_buffer *real_buf = NULL;

    PR_ASSERT(env != NULL && buf != NULL);

    if (JSS_PR_unwrapJBuffer(env, buf, &real_buf) != PR_SUCCESS ||
            real_buf == NULL) {
        return;
    }

    jb_free(real_buf);
    JSS_clearPtrFromProxy(env, buf);
}
