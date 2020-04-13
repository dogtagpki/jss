#include <nspr.h>
#include <nss.h>
#include <jni.h>

#pragma once

PRStatus JSS_NSS_getSSLClientCert(JNIEnv *env, jobject sslfd_proxy, CERTCertificate **cert);

PRStatus JSS_NSS_getSSLAlertSentList(JNIEnv *env, jobject sslfd_proxy, jobject *list);

PRStatus JSS_NSS_getSSLAlertReceivedList(JNIEnv *env, jobject sslfd_proxy, jobject *list);

PRStatus JSS_NSS_addSSLAlert(JNIEnv *env, jobject sslfd_proxy, jobject list, const SSLAlert *alert);

PRStatus JSS_NSS_getGlobalRef(JNIEnv *env, jobject sslfd_proxy, jobject *global_ref);

void
JSSL_SSLFDAlertReceivedCallback(const PRFileDesc *fd, void *arg, const SSLAlert *alert);

void
JSSL_SSLFDAlertSentCallback(const PRFileDesc *fd, void *arg, const SSLAlert *alert);

SECStatus
JSSL_SSLFDCertSelectionCallback(void *arg,
                                PRFileDesc *fd,
                                CERTDistNames *caNames,
                                CERTCertificate **pRetCert,
                                SECKEYPrivateKey **pRetKey);

void
JSSL_SSLFDHandshakeComplete(PRFileDesc *fd, void *client_data);
