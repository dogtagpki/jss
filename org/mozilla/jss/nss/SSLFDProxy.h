#include <nspr.h>
#include <nss.h>
#include <jni.h>

#pragma once

PRStatus JSS_NSS_getSSLClientCert(JNIEnv *env, jobject sslfd_proxy, CERTCertificate **cert);

SECStatus
JSSL_SSLFDCertSelectionCallback(void *arg,
                                PRFileDesc *fd,
                                CERTDistNames *caNames,
                                CERTCertificate **pRetCert,
                                SECKEYPrivateKey **pRetKey);
