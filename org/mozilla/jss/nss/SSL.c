#include <nspr.h>
#include <nss.h>
#include <ssl.h>
#include <sslerr.h>
#include <limits.h>
#include <stdint.h>
#include <jni.h>

#include "jssl.h"
#include "java_ids.h"
#include "jss_exceptions.h"
#include "jssutil.h"
#include "pk11util.h"
#include "PRFDProxy.h"
#include "SSLVersionRange.h"

#include "_jni/org_mozilla_jss_nss_SSL.h"

jobject JSS_NewSecurityStatusResult(JNIEnv *env, int on, char *cipher,
    int keySize, int secretKeySize, char *issuer, char *subject)
{
    jclass resultClass;
    jmethodID constructor;
    jobject result = NULL;
    jbyteArray cipher_java = NULL;
    jbyteArray issuer_java = NULL;
    jbyteArray subject_java = NULL;

    PR_ASSERT(env != NULL);

    resultClass = (*env)->FindClass(env, SECURITY_STATUS_CLASS_NAME);
    if (resultClass == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    constructor = (*env)->GetMethodID(env, resultClass, PLAIN_CONSTRUCTOR,
        SECURITY_STATUS_CONSTRUCTOR_SIG);
    if (constructor == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    if (cipher) {
        cipher_java = JSS_ToByteArray(env, cipher, strlen(cipher));
    }

    if (issuer) {
        issuer_java = JSS_ToByteArray(env, issuer, strlen(issuer));
    }

    if (subject) {
        subject_java = JSS_ToByteArray(env, subject, strlen(subject));
    }

    result = (*env)->NewObject(env, resultClass, constructor, on, cipher_java,
        keySize, secretKeySize, issuer_java, subject_java);

finish:
    return result;
}

JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_nss_SSL_ImportFD(JNIEnv *env, jclass clazz, jobject model,
    jobject fd)
{
    PRFileDesc *result = NULL;
    PRFileDesc *real_model = NULL;
    PRFileDesc *real_fd = NULL;

    PR_ASSERT(env != NULL);

    /* Note: NSS calling semantics state that either model or fd can be
     * NULL; so when the Java Object is not-NULL, dereference it. */
    if (model != NULL && JSS_PR_getPRFileDesc(env, model, &real_model) != PR_SUCCESS) {
        return NULL;
    }

    if (fd != NULL && JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return NULL;
    }

    result = SSL_ImportFD(real_model, real_fd);

    return JSS_PR_wrapPRFDProxy(env, &result);
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SSL_OptionSet(JNIEnv *env, jclass clazz, jobject fd,
    jint option, jint val)
{
    PRFileDesc *real_fd = NULL;

    PR_ASSERT(env != NULL && fd != NULL);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return SECFailure;
    }

    return SSL_OptionSet(real_fd, option, val);
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SSL_OptionGet(JNIEnv *env, jclass clazz, jobject fd,
    jint option)
{
    PRFileDesc *real_fd = NULL;
    int result = -1;

    PR_ASSERT(env != NULL && fd != NULL);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        JSS_throwMsg(env, INVALID_PARAMETER_EXCEPTION,
            "Unable to dereference fd object");
        return result;
    }

    if (SSL_OptionGet(real_fd, option, &result) != SECSuccess) {
        JSS_throwMsg(env, ILLEGAL_ARGUMENT_EXCEPTION,
            "Unknown option to get or getting option failed");
    }
    return result;
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SSL_SetURL(JNIEnv *env, jclass clazz, jobject fd,
    jstring url)
{
    PRFileDesc *real_fd = NULL;
    char *real_url = NULL;

    PR_ASSERT(env != NULL && fd != NULL);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return SECFailure;
    }

    real_url = (char *)(*env)->GetStringUTFChars(env, url, NULL);
    if (real_url == NULL) {
        return SECFailure;
    }

    return SSL_SetURL(real_fd, real_url);
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SSL_CipherPrefSet(JNIEnv *env, jclass clazz,
    jobject fd, jint cipher, jboolean enabled)
{
    PRFileDesc *real_fd = NULL;

    PR_ASSERT(env != NULL && fd != NULL);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return SECFailure;
    }

    return SSL_CipherPrefSet(real_fd, cipher, enabled);
}

JNIEXPORT jboolean JNICALL
Java_org_mozilla_jss_nss_SSL_CipherPrefGet(JNIEnv *env, jclass clazz,
    jobject fd, jint cipher)
{
    PRFileDesc *real_fd = NULL;
    int enabled = false;

    PR_ASSERT(env != NULL && fd != NULL);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        JSS_throwMsg(env, INVALID_PARAMETER_EXCEPTION,
            "Unable to dereference fd object");
        return enabled;
    }

    if (SSL_CipherPrefGet(real_fd, cipher, &enabled) != SECSuccess) {
        JSS_throwMsg(env, ILLEGAL_ARGUMENT_EXCEPTION,
            "Unknown cipher suite to get or getting its value failed");
        return enabled;
    }

    return enabled;
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SSL_VersionRangeSetNative(JNIEnv *env, jclass clazz,
    jobject fd, jint min_ssl, jint max_ssl)
{
    PRFileDesc *real_fd = NULL;
    SSLVersionRange vrange;

    PR_ASSERT(env != NULL && fd != NULL);

    if (min_ssl < 0 || min_ssl >= JSSL_enums_size ||
            max_ssl < 0 || max_ssl >= JSSL_enums_size)
    {
        char buf[128];
        snprintf(buf, 128,
                 "SSL.VersionRangeSetNative(): for min=%d max=%d failed - out of range for array JSSL_enums size: %d",
                 min_ssl, max_ssl, JSSL_enums_size);
        JSSL_throwSSLSocketException(env, buf);
        return SECFailure;
    }

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        JSS_throwMsg(env, INVALID_PARAMETER_EXCEPTION,
            "Unable to dereference fd object");
        return SECFailure;
    }

    vrange.min = JSSL_enums[min_ssl];
    vrange.max = JSSL_enums[max_ssl];

    return SSL_VersionRangeSet(real_fd, &vrange);
}

JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_nss_SSL_VersionRangeGet(JNIEnv *env, jclass clazz,
    jobject fd)
{
    PRFileDesc *real_fd = NULL;
    SSLVersionRange vrange;

    PR_ASSERT(env != NULL && fd != NULL);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        JSS_throwMsg(env, INVALID_PARAMETER_EXCEPTION,
            "Unable to dereference fd object");
        return NULL;
    }

    if (SSL_VersionRangeGet(real_fd, &vrange) != SECSuccess) {
        JSS_throwMsg(env, INVALID_PARAMETER_EXCEPTION,
            "Unable to dereference fd object");
        return NULL;
    }

    return JSS_SSL_wrapVersionRange(env, vrange);
}

JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_nss_SSL_SecurityStatus(JNIEnv *env, jclass clazz,
    jobject fd)
{
    PRFileDesc *real_fd = NULL;
    int on;
    char *cipher;
    int keySize;
    int secretKeySize;
    char *issuer;
    char *subject;

    PR_ASSERT(env != NULL && fd != NULL);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return NULL;
    }

    if (SSL_SecurityStatus(real_fd, &on, &cipher, &keySize, &secretKeySize, &issuer, &subject) != SECSuccess) {
        return NULL;
    }

    return JSS_NewSecurityStatusResult(env, on, cipher, keySize, secretKeySize,
        issuer, subject);
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SSL_ResetHandshake(JNIEnv *env, jclass clazz,
    jobject fd, jboolean asServer)
{
    PRFileDesc *real_fd = NULL;

    PR_ASSERT(env != NULL && fd != NULL);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return SECFailure;
    }

    return SSL_ResetHandshake(real_fd, asServer);
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SSL_ForceHandshake(JNIEnv *env, jclass clazz,
    jobject fd)
{
    PRFileDesc *real_fd = NULL;

    PR_ASSERT(env != NULL && fd != NULL);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return SECFailure;
    }

    return SSL_ForceHandshake(real_fd);
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SSL_ConfigSecureServer(JNIEnv *env, jclass clazz,
    jobject fd, jobject cert, jobject key, jint kea)
{
    PRFileDesc *real_fd = NULL;
    CERTCertificate *real_cert = NULL;
    SECKEYPrivateKey *real_key = NULL;

    PR_ASSERT(env != NULL && fd != NULL);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return SECFailure;
    }

    if (JSS_PK11_getCertPtr(env, cert, &real_cert) != PR_SUCCESS) {
        return SECFailure;
    }

    if (JSS_PK11_getPrivKeyPtr(env, key, &real_key) != PR_SUCCESS) {
        return SECFailure;
    }

    return SSL_ConfigSecureServer(real_fd, real_cert, real_key, kea);
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SSL_ConfigServerCert(JNIEnv *env, jclass clazz,
    jobject fd, jobject cert, jobject key)
{
    PRFileDesc *real_fd = NULL;
    CERTCertificate *real_cert = NULL;
    SECKEYPrivateKey *real_key = NULL;

    PR_ASSERT(env != NULL && fd != NULL);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return SECFailure;
    }

    if (JSS_PK11_getCertPtr(env, cert, &real_cert) != PR_SUCCESS) {
        return SECFailure;
    }

    if (JSS_PK11_getPrivKeyPtr(env, key, &real_key) != PR_SUCCESS) {
        return SECFailure;
    }

    return SSL_ConfigServerCert(real_fd, real_cert, real_key, NULL, 0);
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SSL_ConfigServerSessionIDCache(JNIEnv *env, jclass clazz,
    jint maxCacheEntries, jlong timeout, jlong ssl3_timeout, jstring directory)
{
    const char *dir_path;
    SECStatus ret = SECFailure;

    PR_ASSERT(env != NULL);

    dir_path = JSS_RefJString(env, directory);

    ret = SSL_ConfigServerSessionIDCache(maxCacheEntries, timeout,
        ssl3_timeout, dir_path);

    JSS_DerefJString(env, directory, dir_path);
    return ret;
}

JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_nss_SSL_PeerCertificate(JNIEnv *env, jclass clazz,
    jobject fd)
{
    PRFileDesc *real_fd = NULL;
    CERTCertificate *cert = NULL;

    PR_ASSERT(env != NULL && fd != NULL);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return NULL;
    }

    cert = SSL_PeerCertificate(real_fd);
    if (cert == NULL) {
        return NULL;
    }

    return JSS_PK11_wrapCert(env, &cert);
}

JNIEXPORT jobjectArray JNICALL
Java_org_mozilla_jss_nss_SSL_PeerCertificateChain(JNIEnv *env, jclass clazz,
    jobject fd)
{
    PRFileDesc *real_fd = NULL;
    CERTCertList *chain = NULL;

    PR_ASSERT(env != NULL && fd != NULL);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return NULL;
    }

    chain = SSL_PeerCertificateChain(real_fd);
    int error = PORT_GetError();

    if (chain == NULL && error == SSL_ERROR_NO_CERTIFICATE) {
        return NULL;
    } else if (chain == NULL /* && error != SSL_ERROR_NO_CERTIFICATE */) {
        JSS_throwMsgPrErrArg(env, SECURITY_EXCEPTION,
            "Unable to construct peer certificate chain.", error);
        return NULL;
    }

    return JSS_PK11_wrapCertChain(env, &chain);
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_getSSLRequestCertificate(JNIEnv *env, jclass clazz)
{
    return SSL_REQUEST_CERTIFICATE;
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_getSSLRequireCertificate(JNIEnv *env, jclass clazz)
{
    return SSL_REQUIRE_CERTIFICATE;
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_getSSLSECSuccess(JNIEnv *env, jclass clazz)
{
    return SECSuccess;
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_getSSLSECFailure(JNIEnv *env, jclass clazz)
{
    return SECFailure;
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_getSSLSECWouldBlock(JNIEnv *env, jclass clazz)
{
    return SECWouldBlock;
}
