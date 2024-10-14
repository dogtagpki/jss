#include <nspr.h>
#include <nss.h>
#include <ssl.h>
#include <pk11pub.h>
#include <jni.h>
#include <secerr.h>

#include "java_ids.h"
#include "jssutil.h"
#include "pk11util.h"
#include "jss_exceptions.h"
#include "SSLFDProxy.h"
#include "GlobalRefProxy.h"

PRStatus
JSS_NSS_getSSLClientCert(JNIEnv *env, jobject sslfd_proxy, CERTCertificate **cert)
{
    jclass sslfdProxyClass;
    jfieldID certField;
    jobject certProxy;

    PR_ASSERT(env != NULL && sslfd_proxy != NULL && cert != NULL);

    /* Resolve the clientCert field on a SSLFDProxy object. */
    sslfdProxyClass = (*env)->GetObjectClass(env, sslfd_proxy);
    if (sslfdProxyClass == NULL) {
        return PR_FAILURE;
    }

    certField = (*env)->GetFieldID(env, sslfdProxyClass,
                                   SSLFD_PROXY_CLIENT_CERT_FIELD,
                                   SSLFD_PROXY_CLIENT_CERT_SIG);
    if (certField == NULL) {
        return PR_FAILURE;
    }

    certProxy = (*env)->GetObjectField(env, sslfd_proxy, certField);

    if (certProxy == NULL) {
        *cert = NULL;
        return PR_SUCCESS;
    }

    /* Get the underlying CERTCertificate pointer from the clientCert
     * (of type PK11Cert) object. */
    return JSS_PK11_getCertPtr(env, certProxy, cert);
}

PRStatus
JSS_NSS_getGlobalRef(JNIEnv *env, jobject sslfd_proxy, jobject *global_ref)
{
    PR_ASSERT(env != NULL && sslfd_proxy != NULL && global_ref != NULL);

    if (JSS_getPtrFromProxyOwner(env, sslfd_proxy, "globalRef",
                                 "L" GLOBAL_REF_PROXY_CLASS_NAME ";",
                                 (void **)global_ref) == PR_FAILURE ||
        *global_ref == NULL)
    {
        JSS_throw(env, NULL_POINTER_EXCEPTION);
        return PR_FAILURE;
    }

    return PR_SUCCESS;
}

jobject
JSS_NSS_createSSLAlert(JNIEnv *env, jobject sslfd_proxy, const SSLAlert *alert)
{
    jclass eventClass;
    jmethodID eventConstructor;
    jobject event;

    PR_ASSERT(env != NULL && sslfd_proxy != NULL && alert != NULL);

    /* Build the new alert event object (org.mozilla.jss.ssl.SSLAlertEvent). */
    eventClass = (*env)->FindClass(env, SSL_ALERT_EVENT_CLASS);
    if (eventClass == NULL) {
        return NULL;
    }

    eventConstructor = (*env)->GetMethodID(env, eventClass, "<init>",
                                           "(L" SSLFD_PROXY_CLASS_NAME ";II)V");
    if (eventConstructor == NULL) {
        return NULL;
    }

    event = (*env)->NewObject(env, eventClass, eventConstructor,
                              sslfd_proxy, (int)alert->level,
                              (int)alert->description);
    return event;
}

void
JSSL_SSLFDAlertReceivedCallback(const PRFileDesc *fd, void *arg, const SSLAlert *alert)
{
    JNIEnv *env;
    jobject sslfd_proxy = (jobject)arg;
    jclass sslfdProxyClass;
    jmethodID alertReceivedMethod;
    jobject event;

    if (fd == NULL || arg == NULL || alert == NULL || JSS_javaVM == NULL) {
        return;
    }

    if ((*JSS_javaVM)->AttachCurrentThread(JSS_javaVM, (void**)&env, NULL) != JNI_OK || env == NULL) {
        return;
    }

    sslfdProxyClass = (*env)->GetObjectClass(env, sslfd_proxy);

    if (sslfdProxyClass == NULL) {
        return;
    }

    alertReceivedMethod = (*env)->GetMethodID(
        env,
        sslfdProxyClass,
        "alertReceived",
        "(L" SSL_ALERT_EVENT_CLASS ";)V");

    if (alertReceivedMethod == NULL) {
        return;
    }

    // event = new SSLAlertEvent()
    event = JSS_NSS_createSSLAlert(env, sslfd_proxy, alert);

    if (event == NULL) {
        return;
    }

    // sslfd_proxy.alertReceived(event)
    (void)(*env)->CallVoidMethod(env, sslfd_proxy, alertReceivedMethod, event);
}

void
JSSL_SSLFDAlertSentCallback(const PRFileDesc *fd, void *arg, const SSLAlert *alert)
{
    JNIEnv *env;
    jobject sslfd_proxy = (jobject)arg;
    jclass sslfdProxyClass;
    jmethodID alertSentMethod;
    jobject event;

    if (fd == NULL || arg == NULL || alert == NULL || JSS_javaVM == NULL) {
        return;
    }

    if ((*JSS_javaVM)->AttachCurrentThread(JSS_javaVM, (void**)&env, NULL) != JNI_OK || env == NULL) {
        return;
    }

    sslfdProxyClass = (*env)->GetObjectClass(env, sslfd_proxy);

    if (sslfdProxyClass == NULL) {
        return;
    }

    alertSentMethod = (*env)->GetMethodID(
        env,
        sslfdProxyClass,
        "alertSent",
        "(L" SSL_ALERT_EVENT_CLASS ";)V");

    if (alertSentMethod == NULL) {
        return;
    }

    // event = new SSLAlertEvent()
    event = JSS_NSS_createSSLAlert(env, sslfd_proxy, alert);

    if (event == NULL) {
        return;
    }

    // sslfd_proxy.alertSent(event)
    (void)(*env)->CallVoidMethod(env, sslfd_proxy, alertSentMethod, event);
}

SECStatus
JSSL_SSLFDCertSelectionCallback(void *arg,
                                PRFileDesc *fd,
                                CERTDistNames *caNames,
                                CERTCertificate **pRetCert,
                                SECKEYPrivateKey **pRetKey)
{
    CERTCertificate *cert = arg;
    PK11SlotList *slotList;
    PK11SlotListElement *slotElement;
    SECKEYPrivateKey *privkey = NULL;

    /* Certificate selection for client auth requires that we pass both the
     * certificate (in *pRetCert) and its key (in *pRetKey). We iterate over
     * all slots that the certificate is in, looking for a private key in
     * any of them. Once found, we return the private key. */
    slotList = PK11_GetAllSlotsForCert(cert, NULL /* unused arg */);
    if (slotList == NULL) {
        return SECFailure;
    }

    for (slotElement = slotList->head; slotElement; slotElement = slotElement->next) {
        privkey = PK11_FindPrivateKeyFromCert(slotElement->slot, cert, NULL /* pinarg */);
        if (privkey != NULL) {
            break;
        }
    }

    /* Always free the slot list. */
    PK11_FreeSlotList(slotList);

    /* If the certificate isn't found, return SECFailure. */
    if (privkey == NULL) {
        return SECFailure;
    }

    *pRetCert = CERT_DupCertificate(cert);
    *pRetKey = privkey;
    return SECSuccess;
}

void
JSSL_SSLFDHandshakeComplete(PRFileDesc *fd, void *client_data)
{
    JNIEnv *env = NULL;
    jobject sslfd_proxy = (jobject)client_data;
    jclass sslfdProxyClass;
    jmethodID handshakeCompletedMethod;

    jclass eventClass;
    jmethodID eventConstructor;
    jobject event;

    if (fd == NULL || client_data == NULL || JSS_javaVM == NULL) {
        return;
    }

    if ((*JSS_javaVM)->AttachCurrentThread(JSS_javaVM, (void**)&env, NULL) != JNI_OK || env == NULL) {
        return;
    }

    sslfdProxyClass = (*env)->GetObjectClass(env, sslfd_proxy);

    if (sslfdProxyClass == NULL) {
        return;
    }

    handshakeCompletedMethod = (*env)->GetMethodID(
        env,
        sslfdProxyClass,
        "handshakeCompleted",
        "(L" SSL_HANDSHAKE_COMPLETED_EVENT_CLASS ";)V");

    if (handshakeCompletedMethod == NULL) {
        return;
    }

    eventClass = (*env)->FindClass(env, SSL_HANDSHAKE_COMPLETED_EVENT_CLASS);

    if (eventClass == NULL) {
        return;
    }

    eventConstructor = (*env)->GetMethodID(
        env,
        eventClass,
        "<init>",
        "(L" SSLFD_PROXY_CLASS_NAME ";)V");

    if (eventConstructor == NULL) {
        return;
    }

    // event = new SSLHandshakeCompletedEvent()
    event = (*env)->NewObject(
        env,
        eventClass,
        eventConstructor,
        sslfd_proxy);

    if (event == NULL) {
        return;
    }

    // sslfd_proxy.handshakeCompleted(event)
    (void)(*env)->CallVoidMethod(env, sslfd_proxy, handshakeCompletedMethod, event);
}

SECStatus
JSSL_SSLFDAsyncCertAuthCallback(void *arg, PRFileDesc *fd, PRBool checkSig, PRBool isServer)
{
    /* We know that arg is our GlobalRefProxy instance pointing to the
     * SSLFDProxy class instance. This lets us ignore the isServer parameter,
     * because we can infer that from our JSSEngine instance. Additionally,
     * because we have no control over whether or not our TrustManagers do
     * signature verification (we hope they do!) we ignore checkSig as well.
     *
     * All we need to do then is set SSLFDProxy@fd_ref's needCertValidation
     * to true.
     */
    JNIEnv *env = NULL;
    jobject sslfd_proxy = (jobject) arg;
    jclass sslfdProxyClass;
    jfieldID needCertValidationField;

    if (arg == NULL || fd == NULL || JSS_javaVM == NULL) {
        return SECFailure;
    }

    if ((*JSS_javaVM)->AttachCurrentThread(JSS_javaVM, (void**)&env, NULL) != JNI_OK || env == NULL) {
        return SECFailure;
    }

    sslfdProxyClass = (*env)->GetObjectClass(env, sslfd_proxy);
    if (sslfdProxyClass == NULL) {
        return SECFailure;
    }

    needCertValidationField = (*env)->GetFieldID(env, sslfdProxyClass,
                                                 "needCertValidation", "Z");
    if (needCertValidationField == NULL) {
        return SECFailure;
    }

    (*env)->SetBooleanField(env, sslfd_proxy, needCertValidationField, JNI_TRUE);

    return SECWouldBlock;
}

SECStatus
JSSL_SSLFDSyncCertAuthCallback(void *arg, PRFileDesc *fd, PRBool checkSig, PRBool isServer)
{
    /* We know that arg is our GlobalRefProxy instance pointing to the
     * SSLFDProxy class instance. This lets us ignore the isServer parameter,
     * because we can infer that from our JSSEngine instance. Additionally,
     * because we have no control over whether or not our TrustManagers do
     * signature verification (we hope they do!) we ignore checkSig as well.
     *
     * All we need to do then is call SSLFDProxy@fd_ref's
     * invokeCertAuthHandler() method.
     */
    JNIEnv *env = NULL;
    jobject sslfd_proxy = (jobject) arg;
    jclass sslfdProxyClass;
    jmethodID certAuthHandlerMethod;
    PRErrorCode ret;

    if (arg == NULL || fd == NULL || JSS_javaVM == NULL) {
        PR_SetError(SEC_ERROR_INVALID_ARGS, 0);
        return SECFailure;
    }

    if ((*JSS_javaVM)->AttachCurrentThread(JSS_javaVM, (void**)&env, NULL) != JNI_OK || env == NULL) {
        PR_SetError(PR_UNKNOWN_ERROR, 0);
        return SECFailure;
    }

    sslfdProxyClass = (*env)->GetObjectClass(env, sslfd_proxy);
    if (sslfdProxyClass == NULL) {
        PR_SetError(PR_UNKNOWN_ERROR, 0);
        return SECFailure;
    }

    certAuthHandlerMethod = (*env)->GetMethodID(env, sslfdProxyClass,
        "invokeCertAuthHandler", "()I");
    if (certAuthHandlerMethod == NULL) {
        PR_SetError(PR_UNKNOWN_ERROR, 0);
        return SECFailure;
    }

    ret = (*env)->CallIntMethod(env, sslfd_proxy, certAuthHandlerMethod);
    if ((*env)->ExceptionOccurred(env) != NULL) {
        ret = PR_UNKNOWN_ERROR;
    }

    PR_SetError(ret, 0);

    if (ret == 0) {
        return SECSuccess;
    }

    return SECFailure;
}

SECStatus
JSSL_SSLFDAsyncBadCertCallback(void *arg, PRFileDesc *fd)
{
    /* We know that arg is our GlobalRefProxy instance pointing to the
     * SSLFDProxy class instance. This lets us ignore the PRFileDesc
     * parameter because we already have a reference to it via arg.
     *
     * All we need to do then is set SSLFDProxy@fd_ref's needBadCertValidation
     * to true.
     */
    JNIEnv *env = NULL;
    jobject sslfd_proxy = (jobject) arg;
    jclass sslfdProxyClass;
    jfieldID needBadCertValidationField;
    jfieldID badCertErrorField;
    int cert_error = PR_GetError();

    if (arg == NULL || fd == NULL || JSS_javaVM == NULL) {
        return SECFailure;
    }

    if ((*JSS_javaVM)->AttachCurrentThread(JSS_javaVM, (void**)&env, NULL) != JNI_OK || env == NULL) {
        return SECFailure;
    }

    sslfdProxyClass = (*env)->GetObjectClass(env, sslfd_proxy);
    if (sslfdProxyClass == NULL) {
        return SECFailure;
    }

    needBadCertValidationField = (*env)->GetFieldID(env, sslfdProxyClass,
                                                    "needBadCertValidation", "Z");
    if (needBadCertValidationField == NULL) {
        return SECFailure;
    }

    badCertErrorField = (*env)->GetFieldID(env, sslfdProxyClass,
                                           "badCertError", "I");
    if (badCertErrorField == NULL) {
        return SECFailure;
    }

    (*env)->SetBooleanField(env, sslfd_proxy, needBadCertValidationField, JNI_TRUE);
    (*env)->SetIntField(env, sslfd_proxy, needBadCertValidationField, cert_error);

    return SECWouldBlock;
}

SECStatus
JSSL_SSLFDSyncBadCertCallback(void *arg, PRFileDesc *fd)
{
    /* We know that arg is our GlobalRefProxy instance pointing to the
     * SSLFDProxy class instance. This lets us ignore the PRFileDesc
     * parameter because we already have a reference to it via arg.
     *
     * All we need to do then is call SSLFDProxy@fd_ref's
     * invokeBadCertHandler() method.
     */
    JNIEnv *env = NULL;
    jobject sslfd_proxy = (jobject) arg;
    jclass sslfdProxyClass;
    jmethodID badCertHandlerMethod;
    PRErrorCode ret;
    int cert_error = PR_GetError();

    if (arg == NULL || fd == NULL || JSS_javaVM == NULL) {
        PR_SetError(SEC_ERROR_INVALID_ARGS, 0);
        return SECFailure;
    }

    if ((*JSS_javaVM)->AttachCurrentThread(JSS_javaVM, (void**)&env, NULL) != JNI_OK || env == NULL) {
        PR_SetError(PR_UNKNOWN_ERROR, 0);
        return SECFailure;
    }

    sslfdProxyClass = (*env)->GetObjectClass(env, sslfd_proxy);
    if (sslfdProxyClass == NULL) {
        PR_SetError(PR_UNKNOWN_ERROR, 0);
        return SECFailure;
    }

    badCertHandlerMethod = (*env)->GetMethodID(env, sslfdProxyClass,
        "invokeBadCertHandler", "(I)I");
    if (badCertHandlerMethod == NULL) {
        PR_SetError(PR_UNKNOWN_ERROR, 0);
        return SECFailure;
    }

    ret = (*env)->CallIntMethod(env, sslfd_proxy, badCertHandlerMethod, cert_error);
    if ((*env)->ExceptionOccurred(env) != NULL) {
        ret = PR_UNKNOWN_ERROR;
    }

    PR_SetError(ret, 0);

    if (ret == 0) {
        return SECSuccess;
    }

    return SECFailure;
}

