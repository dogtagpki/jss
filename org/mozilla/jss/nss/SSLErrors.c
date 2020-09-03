#include <nspr.h>
#include <limits.h>
#include <stdint.h>
#include <jni.h>
#include <nss.h>
#include <ssl.h>
#include <sslerr.h>

#include "jssutil.h"
#include "PRFDProxy.h"
#include "BufferProxy.h"
#include "BufferPRFD.h"

#include "_jni/org_mozilla_jss_nss_SECErrors.h"

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SSLErrors_getBadCertDomain(JNIEnv *env, jclass clazz)
{
    return SSL_ERROR_BAD_CERT_DOMAIN;
}
