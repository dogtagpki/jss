#include <nspr.h>
#include <jni.h>

#include "java_ids.h"
#include "jssutil.h"
#include "ByteBufferProxy.h"

jobject
JSS_PR_wrapJByteBuffer(JNIEnv *env, j_bytebuffer **buffer)
{
    jbyteArray pointer = NULL;
    jclass proxyClass;
    jmethodID constructor;
    jobject bufferObj = NULL;

    PR_ASSERT(env != NULL && buffer != NULL && *buffer != NULL);

    /* convert pointer to byte array */
    pointer = JSS_ptrToByteArray(env, *buffer);

    /*
     * Lookup the class and constructor
     */
    proxyClass = (*env)->FindClass(env, BYTE_BUFFER_PROXY_CLASS_NAME);
    if (proxyClass == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }
    constructor = (*env)->GetMethodID(env, proxyClass,
                            PLAIN_CONSTRUCTOR,
                            BYTE_BUFFER_PROXY_CONSTRUCTOR_SIG);
    if (constructor == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    /* call the constructor */
    bufferObj = (*env)->NewObject(env, proxyClass, constructor, pointer);

finish:
    *buffer = NULL;

    PR_ASSERT(bufferObj || (*env)->ExceptionOccurred(env));
    return bufferObj;
}

PRStatus
JSS_PR_unwrapJByteBuffer(JNIEnv *env, jobject buffer_proxy, j_bytebuffer **buffer)
{
    return JSS_getPtrFromProxy(env, buffer_proxy, (void**)buffer);
}
