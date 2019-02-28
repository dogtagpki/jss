#include <nspr.h>
#include <limits.h>
#include <stdint.h>
#include <jni.h>

#include "jssutil.h"
#include "PRFDProxy.h"

#include "_jni/org_mozilla_jss_nss_PR.h"

JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_nss_PR_Open(JNIEnv *env, jclass clazz, jstring name,
    jint flags, jint mode)
{
    PRFileDesc *fd;
    char *path;

    PR_ASSERT(env != NULL);

    path = (char *)(*env)->GetStringUTFChars(env, name, NULL);
    if (path == NULL) {
         return NULL;
    }

    fd = PR_Open(path, flags, mode);
    if (fd == NULL) {
        return NULL;
    }

    return JSS_PR_wrapPRFDProxy(env, &fd);
}

JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_nss_PR_NewTCPSocket(JNIEnv *env, jclass clazz)
{
    PRFileDesc *fd;

    PR_ASSERT(env != NULL);

    fd = PR_NewTCPSocket();
    if (fd == NULL) {
        return NULL;
    }

    return JSS_PR_wrapPRFDProxy(env, &fd);
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_PR_Close(JNIEnv *env, jclass clazz, jobject fd)
{
    PRFileDesc *real_fd = NULL;

    PR_ASSERT(env != NULL);

    if (fd == NULL) {
        return PR_SUCCESS;
    }

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return PR_FAILURE;
    }

    return PR_Close(real_fd);
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_PR_Shutdown(JNIEnv *env, jclass clazz, jobject fd,
    jint how)
{
    PRFileDesc *real_fd = NULL;

    PR_ASSERT(env != NULL);

    if (fd == NULL) {
        return PR_SUCCESS;
    }

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return PR_FAILURE;
    }

    return PR_Shutdown(real_fd, how);
}

JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_nss_PR_Read(JNIEnv *env, jclass clazz, jobject fd,
    jint amount)
{
    PRFileDesc *real_fd = NULL;
    jobject result = NULL;
    int read_amount = 0;
    uint8_t *buffer = NULL;

    PR_ASSERT(env != NULL && fd != NULL && amount >= 0);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return NULL;
    }

    PR_ASSERT(real_fd != NULL);

    buffer = calloc(amount, sizeof(uint8_t));

    read_amount = PR_Read(real_fd, buffer, amount);

    if (read_amount <= 0) {
        goto done;
    }

    result = JSS_ToByteArray(env, buffer, read_amount);

done:
    free(buffer);
    return result;
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_PR_Write(JNIEnv *env, jclass clazz, jobject fd,
    jbyteArray buf)
{
    PRFileDesc *real_fd = NULL;
    unsigned int real_length = 0;
    int max_length = 0;
    uint8_t *buffer = NULL;
    int result = 0;

    PR_ASSERT(env != NULL && fd != NULL && buf != NULL);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return 0;
    }

    PR_ASSERT(real_fd != NULL);

    real_length = (*env)->GetArrayLength(env, buf);
    if (real_length > INT_MAX) {
        max_length = INT_MAX;
    } else {
        max_length = (int)(real_length % INT_MAX);
    }

    buffer = (uint8_t*)((*env)->GetByteArrayElements(env, buf, NULL));
    if (buffer == NULL) {
        return 0;
    }

    result = PR_Write(real_fd, buffer, max_length);
    (*env)->ReleaseByteArrayElements(env, buf, (jbyte *)buffer, JNI_ABORT);

    return result;
}

JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_nss_PR_Recv(JNIEnv *env, jclass clazz, jobject fd,
    jint amount, jint flags, jlong timeout)
{
    PRFileDesc *real_fd = NULL;
    PRIntervalTime timeout_interval = (PRIntervalTime)(timeout % UINT32_MAX);
    jobject result = NULL;
    int read_amount = 0;
    uint8_t *buffer = NULL;

    PR_ASSERT(env != NULL && fd != NULL && amount >= 0 && flags >= 0 &&
              timeout >= 0 && timeout <= UINT32_MAX);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return NULL;
    }

    PR_ASSERT(real_fd != NULL);

    buffer = calloc(amount, sizeof(uint8_t));

    read_amount = PR_Recv(real_fd, buffer, amount, flags, timeout_interval);

    if (read_amount <= 0) {
        goto done;
    }

    result = JSS_ToByteArray(env, buffer, read_amount);

done:
    free(buffer);
    return result;
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_PR_Send(JNIEnv *env, jclass clazz, jobject fd,
    jbyteArray buf, jint flags, jlong timeout)
{
    PRFileDesc *real_fd = NULL;
    unsigned int real_length = 0;
    int max_length = 0;
    uint8_t *buffer = NULL;
    PRIntervalTime timeout_interval = (PRIntervalTime)(timeout % UINT32_MAX);
    int result = 0;

    PR_ASSERT(env != NULL && fd != NULL && buf != NULL && flags >= 0 &&
              timeout >= 0 && timeout <= UINT32_MAX);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return 0;
    }

    PR_ASSERT(real_fd != NULL);

    real_length = (*env)->GetArrayLength(env, buf);
    if (real_length > INT_MAX) {
        max_length = INT_MAX;
    } else {
        max_length = (int)(real_length % INT_MAX);
    }

    buffer = (uint8_t*)((*env)->GetByteArrayElements(env, buf, NULL));
    if (buffer == NULL) {
        return 0;
    }

    result = PR_Send(real_fd, buffer, max_length, flags, timeout_interval);
    (*env)->ReleaseByteArrayElements(env, buf, (jbyte *)buffer, JNI_ABORT);

    return result;
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_PR_GetError(JNIEnv *env, jclass clazz)
{
    return PR_GetError();
}

JNIEXPORT jbyteArray JNICALL
Java_org_mozilla_jss_nss_PR_GetErrorText(JNIEnv *env, jclass clazz)
{
    ssize_t error_size;
    char *error_text = NULL;
    jbyteArray result = NULL;

    PR_ASSERT(env != NULL);

    error_size = PR_GetErrorTextLength();
    if (error_size < 0) {
        return NULL;
    }

    error_text = calloc(error_size + 1, sizeof(char));
    if (PR_GetErrorText(error_text) == 0) {
        free(error_text);
        return NULL;
    }

    result = JSS_ToByteArray(env, error_text, error_size);
    free(error_text);
    return result;
}
