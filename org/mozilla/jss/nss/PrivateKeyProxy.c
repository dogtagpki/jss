#include <cert.h>
#include <jni.h>

#include "java_ids.h"
#include "jssutil.h"
#include "PrivateKeyProxy.h"

jobject
JSS_wrapSECKEYPrivateKey(JNIEnv *env, SECKEYPrivateKey **key)
{
    jbyteArray pointer = NULL;
    jclass proxyClass;
    jmethodID constructor;
    jobject keyObj = NULL;

    PR_ASSERT(env != NULL && key != NULL && *key != NULL);

    /* convert pointer to byte array */
    pointer = JSS_ptrToByteArray(env, *key);

    /*
     * Lookup the class and constructor
     */
    proxyClass = (*env)->FindClass(env, PRIVATEKEY_PROXY_CLASS_NAME);
    if (proxyClass == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }
    constructor = (*env)->GetMethodID(env, proxyClass,
                            PLAIN_CONSTRUCTOR,
                            PRIVATEKEY_PROXY_CONSTRUCTOR_SIG);
    if (constructor == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    /* call the constructor */
    keyObj = (*env)->NewObject(env, proxyClass, constructor, pointer);

finish:
    *key = NULL;

    PR_ASSERT(keyObj || (*env)->ExceptionOccurred(env));
    return keyObj;
}

PRStatus
JSS_PR_unwrapSECKEYPrivateKey(JNIEnv *env, jobject key_proxy, SECKEYPrivateKey **key)
{
    return JSS_getPtrFromProxy(env, key_proxy, (void**)key);
}
