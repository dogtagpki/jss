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

static PRStatus
JSS_NSS_getEventArrayList(JNIEnv *env, jobject sslfd_proxy, const char *which, jobject *list)
{
    jclass sslfdProxyClass;
    jfieldID eventArrayListField;

    PR_ASSERT(env != NULL && sslfd_proxy != NULL && list != NULL);

    sslfdProxyClass = (*env)->GetObjectClass(env, sslfd_proxy);
    if (sslfdProxyClass == NULL) {
        return PR_FAILURE;
    }

    eventArrayListField = (*env)->GetFieldID(env, sslfdProxyClass, which,
                                             SSLFD_PROXY_EVENT_LIST_SIG);
    if (eventArrayListField == NULL) {
        /* Unlike JSS_NSS_getSSLClientCert above, this is a failure to process
         * the event. We expect the  */
        return PR_FAILURE;
    }

    *list = (*env)->GetObjectField(env, sslfd_proxy, eventArrayListField);
    if (*list == NULL) {
        return PR_FAILURE;
    }

    return PR_SUCCESS;
}

PRStatus
JSS_NSS_getSSLAlertReceivedList(JNIEnv *env, jobject sslfd_proxy, jobject *list)
{
    return JSS_NSS_getEventArrayList(env, sslfd_proxy, "inboundAlerts", list);
}

PRStatus
JSS_NSS_getSSLAlertSentList(JNIEnv *env, jobject sslfd_proxy, jobject *list)
{
    return JSS_NSS_getEventArrayList(env, sslfd_proxy, "outboundAlerts", list);
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

PRStatus
JSS_NSS_addSSLAlert(JNIEnv *env, jobject sslfd_proxy, jobject list,
    const SSLAlert *alert)
{
    jclass eventClass;
    jmethodID eventConstructor;
    jobject event;

    jclass eventListClass;
    jmethodID arrayListAdd;

    PR_ASSERT(env != NULL && sslfd_proxy != NULL && list != NULL && alert != NULL);

    /* Build the new alert event object (org.mozilla.jss.ssl.SSLAlertEvent). */
    eventClass = (*env)->FindClass(env, SSL_ALERT_EVENT_CLASS);
    if (eventClass == NULL) {
        return PR_FAILURE;
    }

    eventConstructor = (*env)->GetMethodID(env, eventClass, "<init>",
                                           "(L" SSLFD_PROXY_CLASS_NAME ";II)V");
    if (eventConstructor == NULL) {
        return PR_FAILURE;
    }

    event = (*env)->NewObject(env, eventClass, eventConstructor,
                              sslfd_proxy, (int)alert->level,
                              (int)alert->description);
    if (event == NULL) {
        return PR_FAILURE;
    }

    /* Add it to the event list. */
    eventListClass = (*env)->GetObjectClass(env, list);
    if (eventListClass == NULL) {
        return PR_FAILURE;
    }

    arrayListAdd = (*env)->GetMethodID(env, eventListClass, "add",
                                       "(Ljava/lang/Object;)Z");
    if (arrayListAdd == NULL) {
        return PR_FAILURE;
    }

    // We ignore the return code: ArrayList.add() always returns true.
    (void)(*env)->CallBooleanMethod(env, list, arrayListAdd, event);
    return PR_SUCCESS;
}

void
JSSL_SSLFDAlertReceivedCallback(const PRFileDesc *fd, void *arg, const SSLAlert *alert)
{
    JNIEnv *env;
    jobject sslfd_proxy = (jobject)arg;
    jobject list;

    if (fd == NULL || arg == NULL || alert == NULL || JSS_javaVM == NULL) {
        return;
    }

    if ((*JSS_javaVM)->AttachCurrentThread(JSS_javaVM, (void**)&env, NULL) != JNI_OK || env == NULL) {
        return;
    }

    if (JSS_NSS_getSSLAlertReceivedList(env, sslfd_proxy, &list) != PR_SUCCESS) {
        return;
    }

    if (JSS_NSS_addSSLAlert(env, sslfd_proxy, list, alert) != PR_SUCCESS) {
        return;
    }
}

void
JSSL_SSLFDAlertSentCallback(const PRFileDesc *fd, void *arg, const SSLAlert *alert)
{
    JNIEnv *env;
    jobject sslfd_proxy = (jobject)arg;
    jobject list;

    if (fd == NULL || arg == NULL || alert == NULL || JSS_javaVM == NULL) {
        return;
    }

    if ((*JSS_javaVM)->AttachCurrentThread(JSS_javaVM, (void**)&env, NULL) != JNI_OK || env == NULL) {
        return;
    }

    if (JSS_NSS_getSSLAlertSentList(env, sslfd_proxy, &list) != PR_SUCCESS) {
        return;
    }

    if (JSS_NSS_addSSLAlert(env, sslfd_proxy, list, alert) != PR_SUCCESS) {
        return;
    }
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
    jfieldID handshakeCompleteField;

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

    handshakeCompleteField = (*env)->GetFieldID(env, sslfdProxyClass,
                                                "handshakeComplete", "Z");
    if (handshakeCompleteField == NULL) {
        return;
    }

    (*env)->SetBooleanField(env, sslfd_proxy, handshakeCompleteField, JNI_TRUE);
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

