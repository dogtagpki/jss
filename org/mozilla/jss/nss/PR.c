#include <nspr.h>
#include <limits.h>
#include <stdint.h>
#include <jni.h>

#include "java_ids.h"
#include "jssutil.h"

#include "_jni/org_mozilla_jss_nss_PR.h"

jobject
JSS_PR_wrapPRFDProxy(JNIEnv *env, PRFileDesc **fd)
{
    jbyteArray pointer = NULL;
    jclass proxyClass;
    jmethodID constructor;
    jobject fdObj = NULL;

    PR_ASSERT(env != NULL && fd != NULL && *fd != NULL);

    /* convert pointer to byte array */
    pointer = JSS_ptrToByteArray(env, *fd);

    /*
     * Lookup the class and constructor
     */
    proxyClass = (*env)->FindClass(env, PRFD_PROXY_CLASS_NAME);
    if(proxyClass == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }
    constructor = (*env)->GetMethodID(env, proxyClass,
                            PLAIN_CONSTRUCTOR,
                            PRFD_PROXY_CONSTRUCTOR_SIG);
    if(constructor == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    /* call the constructor */
    fdObj = (*env)->NewObject(env, proxyClass, constructor, pointer);

finish:
    if (fdObj == NULL && *fd != NULL) {
        /* didn't work, so free resources */
        PR_Close(*fd);
    }

    *fd = NULL;

    PR_ASSERT(fdObj || (*env)->ExceptionOccurred(env));
    return fdObj;
}

PRStatus
JSS_PR_getPRFileDesc(JNIEnv *env, jobject prfd_proxy, PRFileDesc **fd)
{
    return JSS_getPtrFromProxy(env, prfd_proxy, (void**)fd);
}

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

JNIEXPORT void JNICALL
Java_org_mozilla_jss_nss_PR_Shutdown(JNIEnv *env, jclass clazz, jobject fd,
    jint how)
{
    PRFileDesc *real_fd = NULL;

    PR_ASSERT(env != NULL);

    if (fd == NULL) {
        return;
    }

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return;
    }

    PR_Shutdown(real_fd, how);
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
        goto failure;
    }

    result = JSS_ToByteArray(env, buffer, read_amount);

failure:
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
        goto failure;
    }

    result = JSS_ToByteArray(env, buffer, read_amount);

failure:
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
