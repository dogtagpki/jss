#include <nspr.h>
#include <nss.h>
#include <ssl.h>
#include <pk11pub.h>
#include <jni.h>

#include "java_ids.h"
#include "jssutil.h"
#include "pk11util.h"
#include "SSLFDProxy.h"

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

    *pRetCert = cert;
    *pRetKey = privkey;
    return SECSuccess;
}

