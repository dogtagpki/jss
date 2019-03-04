#include <cert.h>
#include <jni.h>

#include "java_ids.h"
#include "jssutil.h"
#include "CertProxy.h"

jobject
JSS_wrapCERTCertificate(JNIEnv *env, CERTCertificate **cert)
{
    jbyteArray pointer = NULL;
    jclass proxyClass;
    jmethodID constructor;
    jobject certObj = NULL;

    PR_ASSERT(env != NULL && cert != NULL && *cert != NULL);

    /* convert pointer to byte array */
    pointer = JSS_ptrToByteArray(env, *cert);

    /*
     * Lookup the class and constructor
     */
    proxyClass = (*env)->FindClass(env, CERT_PROXY_CLASS_NAME);
    if (proxyClass == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }
    constructor = (*env)->GetMethodID(env, proxyClass,
                            PLAIN_CONSTRUCTOR,
                            CERT_PROXY_CONSTRUCTOR_SIG);
    if (constructor == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    /* call the constructor */
    certObj = (*env)->NewObject(env, proxyClass, constructor, pointer);

finish:
    *cert = NULL;

    PR_ASSERT(certObj || (*env)->ExceptionOccurred(env));
    return certObj;
}

PRStatus
JSS_PR_unwrapCERTCertificate(JNIEnv *env, jobject cert_proxy, CERTCertificate **cert)
{
    return JSS_getPtrFromProxy(env, cert_proxy, (void**)cert);
}
