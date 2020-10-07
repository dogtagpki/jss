#include <nspr.h>
#include <jni.h>

#include "java_ids.h"
#include "jssutil.h"

jobject
JSS_PR_wrapStaticVoidPointer(JNIEnv *env, void **ref)
{
    jbyteArray pointer = NULL;
    jclass proxyClass;
    jmethodID constructor;
    jobject refObj = NULL;

    PR_ASSERT(env != NULL && ref != NULL && *ref != NULL);

    /* Convert pointer to byte array. */
    pointer = JSS_ptrToByteArray(env, *ref);

    /* Lookup the class and constructor. */
    proxyClass = (*env)->FindClass(env, STATIC_VOID_POINTER_CLASS_NAME);
    if (proxyClass == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    constructor = (*env)->GetMethodID(env, proxyClass,
                                      PLAIN_CONSTRUCTOR,
                                      STATIC_VOID_POINTER_CONSTRUCTOR_SIG);
    if (constructor == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    /* Call the constructor. */
    refObj = (*env)->NewObject(env, proxyClass, constructor, pointer);

finish:
    PR_ASSERT(refObj || (*env)->ExceptionOccurred(env));
    return refObj;
}

PRStatus
JSS_PR_getStaticVoidRef(JNIEnv *env, jobject ref_proxy, void **ref)
{
    return JSS_getPtrFromProxy(env, ref_proxy, ref);
}
