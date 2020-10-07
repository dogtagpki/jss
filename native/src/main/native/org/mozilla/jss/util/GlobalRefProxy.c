#include <nspr.h>
#include <nss.h>
#include <jni.h>

#include "java_ids.h"
#include "jssutil.h"

jobject
JSS_PR_wrapGlobalRef(JNIEnv *env, jobject *ref)
{
    jbyteArray pointer = NULL;
    jclass proxyClass;
    jmethodID constructor;
    jobject refObj = NULL;

    PR_ASSERT(env != NULL && ref != NULL && *ref != NULL);

    /* Convert pointer to byte array. */
    pointer = JSS_ptrToByteArray(env, *ref);

    /* Lookup the class and constructor. */
    proxyClass = (*env)->FindClass(env, GLOBAL_REF_PROXY_CLASS_NAME);
    if (proxyClass == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    constructor = (*env)->GetMethodID(env, proxyClass,
                                      PLAIN_CONSTRUCTOR,
                                      GLOBAL_REF_CONSTRUCTOR_SIG);
    if (constructor == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    /* Call the constructor. */
    refObj = (*env)->NewObject(env, proxyClass, constructor, pointer);

finish:
    if (refObj == NULL && *ref != NULL) {
        /* Something didn't work, so free resources. */
        (*env)->DeleteGlobalRef(env, *ref);
        *ref = NULL;
    }

    PR_ASSERT(refObj || (*env)->ExceptionOccurred(env));
    return refObj;
}

PRStatus
JSS_PR_getGlobalRef(JNIEnv *env, jobject ref_proxy, jobject *ref)
{
    return JSS_getPtrFromProxy(env, ref_proxy, (void**)ref);
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_util_GlobalRefProxy_releaseNativeResources
    (JNIEnv *env, jobject this)
{
    jobject ref = NULL;

    PR_ASSERT(env != NULL && this != NULL);

    if (JSS_PR_getGlobalRef(env, this, &ref) != PR_SUCCESS) {
        return;
    }

    if (ref != NULL) {
        (*env)->DeleteGlobalRef(env, ref);
    }
}

JNIEXPORT jbyteArray JNICALL
Java_org_mozilla_jss_util_GlobalRefProxy_refOf
    (JNIEnv *env, jobject clazz, jobject obj)
{
    jobject globalRef;

    PR_ASSERT(env != NULL && clazz != NULL && obj != NULL);
    if (obj == NULL) {
        return NULL;
    }

    globalRef = (*env)->NewGlobalRef(env, obj);
    if (globalRef == NULL) {
        return NULL;
    }

    return JSS_ptrToByteArray(env, globalRef);
}
