#include <nspr.h>
#include <limits.h>
#include <stdint.h>
#include <jni.h>
#include <nss.h>
#include <ssl.h>
#include <secerr.h>

#include "jssutil.h"
#include "PRFDProxy.h"
#include "BufferProxy.h"
#include "BufferPRFD.h"

#include "_jni/org_mozilla_jss_nss_SECErrors.h"

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SECErrors_getBadDER(JNIEnv *env, jclass clazz)
{
    return SEC_ERROR_BAD_DER;
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SECErrors_getExpiredCertificate(JNIEnv *env, jclass clazz)
{
    return SEC_ERROR_EXPIRED_CERTIFICATE;
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SECErrors_getCertNotValid(JNIEnv *env, jclass clazz)
{
    return SEC_ERROR_CERT_NOT_VALID;
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SECErrors_getRevokedCertificateOCSP(JNIEnv *env, jclass clazz)
{
    return SEC_ERROR_REVOKED_CERTIFICATE_OCSP;
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SECErrors_getRevokedCertificate(JNIEnv *env, jclass clazz)
{
    return SEC_ERROR_REVOKED_CERTIFICATE;
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SECErrors_getUntrustedIssuer(JNIEnv *env, jclass clazz)
{
    return SEC_ERROR_UNTRUSTED_ISSUER;
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SECErrors_getUntrustedCert(JNIEnv *env, jclass clazz)
{
    return SEC_ERROR_UNTRUSTED_CERT;
}
