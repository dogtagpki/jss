#include <nspr.h>
#include <nss.h>
#include <ssl.h>
#include <sslerr.h>
#include <sslexp.h>
#include <limits.h>
#include <stdint.h>
#include <jni.h>

#include "jssconfig.h"
#include "jssl.h"
#include "java_ids.h"
#include "jss_exceptions.h"
#include "jssutil.h"
#include "pk11util.h"
#include "PRFDProxy.h"
#include "SSLFDProxy.h"
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
    PORT_Free(cipher);
    PORT_Free(issuer);
    PORT_Free(subject);

    return result;
}

jobject JSS_NewSSLChannelInfo(JNIEnv *env, jint protocolVersion,
    jint cipherSuite, jint authKeyBits, jint keaKeyBits, jlong creationTime,
    jlong lastAccessTime, jlong expirationTime, jbyteArray sessionID,
    jint compressionMethod, jboolean extendedMasterSecretUsed,
    jboolean earlyDataAccepted, jint keaType, jint keaGroup, jint symCipher,
    jint macAlgorithm, jint authType, jint signatureScheme,
    jboolean haveNSS334, jint originalKeaGroup, jboolean resumed,
    jboolean haveNSS345, jboolean peerDelegCred)
{
    jclass resultClass;
    jmethodID constructor;
    jobject result = NULL;

    PR_ASSERT(env != NULL);

    resultClass = (*env)->FindClass(env, SSL_CHANNEL_INFO_CLASS_NAME);
    if (resultClass == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    constructor = (*env)->GetMethodID(env, resultClass, PLAIN_CONSTRUCTOR,
        SSL_CHANNEL_INFO_CONSTRUCTOR_SIG);
    if (constructor == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    result = (*env)->NewObject(env, resultClass, constructor, protocolVersion,
        cipherSuite, authKeyBits, keaKeyBits, creationTime, lastAccessTime,
        expirationTime, sessionID, compressionMethod,
        extendedMasterSecretUsed, earlyDataAccepted, keaType, keaGroup,
        symCipher, macAlgorithm, authType, signatureScheme, haveNSS334,
        originalKeaGroup, resumed, haveNSS345, peerDelegCred);

finish:
    return result;
}

jobject JSS_NewSSLPreliminaryChannelInfo(JNIEnv *env, jlong valuesSet,
    jint protocolVersion, jint cipherSuite, jboolean canSendEarlyData,
    jlong maxEarlyDataSize, jboolean haveNSS343, jint zeroRttCipherSuite,
    jboolean haveNSS348, jboolean peerDelegCred, jint authKeyBits,
    jint signatureScheme)
{
    jclass resultClass;
    jmethodID constructor;
    jobject result = NULL;

    PR_ASSERT(env != NULL);

    resultClass = (*env)->FindClass(env, SSL_PRELIMINARY_CHANNEL_INFO_CLASS_NAME);
    if (resultClass == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    constructor = (*env)->GetMethodID(env, resultClass, PLAIN_CONSTRUCTOR,
        SSL_PRELIMINARY_CHANNEL_INFO_CONSTRUCTOR_SIG);
    if (constructor == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    result = (*env)->NewObject(env, resultClass, constructor, valuesSet,
        protocolVersion, cipherSuite, canSendEarlyData, maxEarlyDataSize,
        haveNSS343, zeroRttCipherSuite, haveNSS348, peerDelegCred,
        authKeyBits, signatureScheme);

finish:
    return result;
}

JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_nss_SSL_ImportFD(JNIEnv *env, jclass clazz, jobject model,
    jobject fd)
{
    PR_ASSERT(0);
    JSS_throwMsg(env, NULL_POINTER_EXCEPTION, "JSS JAR/DLL version mismatch");
    return NULL;
}

JNIEXPORT jbyteArray JNICALL
Java_org_mozilla_jss_nss_SSL_ImportFDNative(JNIEnv *env, jclass clazz, jobject model,
    jobject fd)
{
    PRFileDesc *result = NULL;
    PRFileDesc *real_model = NULL;
    PRFileDesc *real_fd = NULL;

    PR_ASSERT(env != NULL);
    PR_SetError(0, 0);

    /* Note: NSS calling semantics state that either model or fd can be
     * NULL; so when the Java Object is not-NULL, dereference it. */
    if (model != NULL && (JSS_PR_getPRFileDesc(env, model, &real_model) != PR_SUCCESS || real_model == NULL)) {
        return NULL;
    }

    if (fd != NULL && (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS || real_fd == NULL)) {
        return NULL;
    }

    result = SSL_ImportFD(real_model, real_fd);
    if (result == NULL) {
        return NULL;
    }

    return JSS_ptrToByteArray(env, result);
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SSL_OptionSet(JNIEnv *env, jclass clazz, jobject fd,
    jint option, jint val)
{
    PRFileDesc *real_fd = NULL;

    PR_ASSERT(env != NULL && fd != NULL);
    PR_SetError(0, 0);

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
    PR_SetError(0, 0);

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
    SECStatus ret = SECFailure;
    const char *real_url = NULL;

    PR_ASSERT(env != NULL && fd != NULL);
    PR_SetError(0, 0);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return ret;
    }

    real_url = JSS_RefJString(env, url);
    if (real_url == NULL) {
        return ret;
    }

    ret = SSL_SetURL(real_fd, real_url);
    JSS_DerefJString(env, url, real_url);
    return ret;
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SSL_CipherPrefSet(JNIEnv *env, jclass clazz,
    jobject fd, jint cipher, jboolean enabled)
{
    PRFileDesc *real_fd = NULL;

    PR_ASSERT(env != NULL && fd != NULL);
    PR_SetError(0, 0);

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
    PR_SetError(0, 0);

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
Java_org_mozilla_jss_nss_SSL_CipherPrefSetDefault(JNIEnv *env, jclass clazz,
    jint cipher, jboolean enabled)
{
    PR_ASSERT(env != NULL);
    PR_SetError(0, 0);

    return SSL_CipherPrefSetDefault(cipher, enabled);
}

JNIEXPORT jboolean JNICALL
Java_org_mozilla_jss_nss_SSL_CipherPrefGetDefault(JNIEnv *env, jclass clazz,
    jint cipher)
{
    int enabled = false;

    PR_ASSERT(env != NULL);
    PR_SetError(0, 0);

    if (SSL_CipherPrefGetDefault(cipher, &enabled) != SECSuccess) {
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
    PR_SetError(0, 0);

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
    PR_SetError(0, 0);

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

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SSL_VersionRangeSetDefaultNative(JNIEnv *env, jclass clazz,
    jint variant_ssl, jint min_ssl, jint max_ssl)
{
    SSLVersionRange vrange;
    SSLProtocolVariant variant;

    PR_ASSERT(env != NULL);
    PR_SetError(0, 0);

    if (min_ssl < 0 || min_ssl >= JSSL_enums_size ||
            max_ssl < 0 || max_ssl >= JSSL_enums_size ||
            variant_ssl < 0 || variant_ssl >= JSSL_enums_size)
    {
        char buf[200];
        snprintf(buf, 200,
                 "SSL.VersionRangeSetDefaultNative(): for min=%d max=%d "
                 "variant=%d failed - out of range for array JSSL_enums "
                 "size: %d", min_ssl, max_ssl, variant_ssl, JSSL_enums_size);
        JSSL_throwSSLSocketException(env, buf);
        return SECFailure;
    }

    vrange.min = JSSL_enums[min_ssl];
    vrange.max = JSSL_enums[max_ssl];
    variant = JSSL_enums[variant_ssl];

    return SSL_VersionRangeSetDefault(variant, &vrange);
}

JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_nss_SSL_VersionRangeGetDefaultNative(JNIEnv *env,
    jclass clazz, jint variant_ssl)
{
    SSLVersionRange vrange;
    SSLProtocolVariant variant;

    PR_SetError(0, 0);

    if (variant_ssl < 0 || variant_ssl >= JSSL_enums_size) {
        char buf[200];
        snprintf(buf, 200,
                 "SSL.VersionRangeGetDefaultNative(): for variant=%d failed: "
                 "out of range for array JSSL_enums size: %d", variant_ssl,
                 JSSL_enums_size);
        JSSL_throwSSLSocketException(env, buf);
        return NULL;
    }

    variant = JSSL_enums[variant_ssl];

    if (SSL_VersionRangeGetDefault(variant, &vrange) != SECSuccess) {
        JSS_throwMsg(env, INVALID_PARAMETER_EXCEPTION,
            "Unable to inquire default SSL version for this protocol");
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
    PR_SetError(0, 0);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return NULL;
    }

    if (SSL_SecurityStatus(real_fd, &on, &cipher, &keySize, &secretKeySize, &issuer, &subject) != SECSuccess) {
        return NULL;
    }

    return JSS_NewSecurityStatusResult(env, on, cipher, keySize, secretKeySize,
        issuer, subject);
}

JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_nss_SSL_GetChannelInfo(JNIEnv *env, jclass clazz,
    jobject fd)
{
    PRFileDesc *real_fd = NULL;
    SSLChannelInfo info = { 0 };
    jint pV = 0;
    jint cS = 0;
    jint aKB = 0;
    jint kKB = 0;
    jlong cT = 0;
    jlong lAT = 0;
    jlong eT = 0;
    jbyteArray sID = NULL;
    jint cM = 0;
    jboolean eMSU = JNI_FALSE;
    jboolean eDA = JNI_FALSE;
    jint kT = 0;
    jint kG = 0;
    jint sC = 0;
    jint mA = 0;
    jint aT = 0;
    jint sS = 0;
    jboolean haveNSS334 = JNI_FALSE;
    jint oKG = 0;
    jboolean r = JNI_FALSE;
    jboolean haveNSS345 = JNI_FALSE;
    jboolean pDC = JNI_FALSE;

    PR_ASSERT(env != NULL && fd != NULL);
    PR_SetError(0, 0);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return NULL;
    }

    if (SSL_GetChannelInfo(real_fd, &info, sizeof(info)) != SECSuccess) {
        return NULL;
    }

    pV = JSSL_enums_reverse(info.protocolVersion);
    cS = info.cipherSuite;

    aKB = info.authKeyBits;
    kKB = info.keaKeyBits;

    cT = info.creationTime;
    lAT = info.lastAccessTime;
    eT = info.expirationTime;
    sID = JSS_ToByteArray(env, info.sessionID, info.sessionIDLength);

    cM = info.compressionMethod;

    eMSU = info.extendedMasterSecretUsed;

    eDA = info.earlyDataAccepted;

    kT = info.keaType;
    kG = info.keaGroup;
    sC = info.symCipher;
    mA = info.macAlgorithm;
    aT = info.authType;
    sS = info.signatureScheme;

#ifdef HAVE_NSS_CHANNEL_INFO_ORIGINAL_KEA_GROUP
    /* The following fields were added in NSS v3.34 and are detected
     * via feature detection in CMake. */
    haveNSS334 = JNI_TRUE;
    oKG = info.originalKeaGroup;
    r = info.resumed;
#endif

#ifdef HAVE_NSS_CHANNEL_INFO_PEER_DELEG_CRED
    /* The following fields were added in NSS v3.45 and are detected
     * via feature detection in CMake. */
    haveNSS345 = JNI_TRUE;
    pDC = info.peerDelegCred;
#endif

    return JSS_NewSSLChannelInfo(env, pV, cS, aKB, kKB, cT, lAT, eT, sID, cM,
                                 eMSU, eDA, kT, kG, sC, mA, aT, sS,
                                 haveNSS334, oKG, r, haveNSS345, pDC);
}

JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_nss_SSL_GetPreliminaryChannelInfo(JNIEnv *env,
    jclass clazz, jobject fd)
{
    PRFileDesc *real_fd = NULL;
    SSLPreliminaryChannelInfo info = { 0 };
    jlong vS = 0;
    jint pV = 0;
    jint cS = 0;
    jboolean cSED = JNI_FALSE;
    jlong mEDS = 0;
    jboolean haveNSS343 = JNI_FALSE;
    jint zRCS = 0;
    jboolean haveNSS348 = JNI_FALSE;
    jboolean pDC = JNI_FALSE;
    jint aKB = 0;
    jint sS = 0;

    PR_ASSERT(env != NULL && fd != NULL);
    PR_SetError(0, 0);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return NULL;
    }

    if (SSL_GetPreliminaryChannelInfo(real_fd, &info, sizeof(info)) != SECSuccess) {
        return NULL;
    }

    vS = info.valuesSet;

    pV = JSSL_enums_reverse(info.protocolVersion);
    cS = info.cipherSuite;

    cSED = info.canSendEarlyData;

    mEDS = info.maxEarlyDataSize;

#ifdef HAVE_NSS_PRELIMINARY_CHANNEL_INFO_ZERO_RTT_CIPHER_SUITE
    /* The following fields were added in NSS v3.43 and are detected
     * via feature detection in CMake. */
    haveNSS343 = JNI_TRUE;
    zRCS = info.zeroRttCipherSuite;
#endif

#ifdef HAVE_NSS_PRELIMINARY_CHANNEL_INFO_PEER_DELEG_CRED
    /* The following fields were added in NSS v3.48 and are detected
     * via feature detection in CMake. */
    haveNSS348 = JNI_TRUE;
    pDC = info.peerDelegCred;
    aKB = info.authKeyBits;
    sS = info.signatureScheme;
#endif

    return JSS_NewSSLPreliminaryChannelInfo(env, vS, pV, cS, cSED, mEDS,
                                            haveNSS343, zRCS, haveNSS348,
                                            pDC, aKB, sS);
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SSL_ResetHandshake(JNIEnv *env, jclass clazz,
    jobject fd, jboolean asServer)
{
    PRFileDesc *real_fd = NULL;

    PR_ASSERT(env != NULL && fd != NULL);
    PR_SetError(0, 0);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return SECFailure;
    }

    return SSL_ResetHandshake(real_fd, asServer);
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SSL_ReHandshake(JNIEnv *env, jclass clazz,
    jobject fd, jboolean flushCache)
{
    PRFileDesc *real_fd = NULL;

    PR_ASSERT(env != NULL && fd != NULL);
    PR_SetError(0, 0);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return SECFailure;
    }

    return SSL_ReHandshake(real_fd, flushCache);
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SSL_ForceHandshake(JNIEnv *env, jclass clazz,
    jobject fd)
{
    PRFileDesc *real_fd = NULL;

    PR_ASSERT(env != NULL && fd != NULL);
    PR_SetError(0, 0);

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
    PR_SetError(0, 0);

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
    PR_SetError(0, 0);

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
    PR_SetError(0, 0);

    dir_path = JSS_RefJString(env, directory);

    ret = SSL_ConfigServerSessionIDCache(maxCacheEntries, timeout,
        ssl3_timeout, dir_path);

    JSS_DerefJString(env, directory, dir_path);
    return ret;
}

JNIEXPORT int JNICALL
Java_org_mozilla_jss_nss_SSL_InvalidateSession(JNIEnv *env, jclass clazz,
    jobject fd)
{
    PRFileDesc *real_fd = NULL;

    PR_ASSERT(env != NULL && fd != NULL);
    PR_SetError(0, 0);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return SECFailure;
    }

    return SSL_InvalidateSession(real_fd);
}

JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_nss_SSL_PeerCertificate(JNIEnv *env, jclass clazz,
    jobject fd)
{
    PRFileDesc *real_fd = NULL;
    CERTCertificate *cert = NULL;

    PR_ASSERT(env != NULL && fd != NULL);
    PR_SetError(0, 0);

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
    PR_SetError(0, 0);

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
Java_org_mozilla_jss_nss_SSL_SendCertificateRequest(JNIEnv *env, jclass clazz,
    jobject fd)
{
    PRFileDesc *real_fd = NULL;

    PR_ASSERT(env != NULL && fd != NULL);
    PR_SetError(0, 0);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return SECFailure;
    }

    return SSL_SendCertificateRequest(real_fd);
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_KeyUpdate(JNIEnv *env, jclass clazz,
    jobject fd, jboolean requestUpdate)
{
    PRFileDesc *real_fd = NULL;

    PR_ASSERT(env != NULL && fd != NULL);
    PR_SetError(0, 0);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return SECFailure;
    }

    return SSL_KeyUpdate(real_fd, requestUpdate == JNI_TRUE ? PR_TRUE : PR_FALSE);
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_AttachClientCertCallback(JNIEnv *env, jclass clazz,
    jobject fd)
{
    PRFileDesc *real_fd = NULL;
    CERTCertificate *real_cert = NULL;

    PR_ASSERT(env != NULL && fd != NULL);
    PR_SetError(0, 0);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return SECFailure;
    }

    if (JSS_NSS_getSSLClientCert(env, fd, &real_cert) != PR_SUCCESS) {
        return SECFailure;
    }

    /* When the returned cert is empty and no error occurred, there was no
     * client certificate specified via SSLFD.SetClientCert(...). Don't add
     * the certificate selection callback handler. */
    if (real_cert == NULL) {
        return SECSuccess;
    }

    return SSL_GetClientAuthDataHook(real_fd, JSSL_SSLFDCertSelectionCallback,
                                     (void *)real_cert);
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_EnableAlertLoggingNative(JNIEnv *env, jclass clazz,
    jobject fd)
{
    PRFileDesc *real_fd = NULL;
    jobject fd_ref = NULL;
    SECStatus ret = SECFailure;

    PR_ASSERT(env != NULL && fd != NULL);
    PR_SetError(0, 0);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return ret;
    }

    if (JSS_NSS_getGlobalRef(env, fd, &fd_ref) != PR_SUCCESS) {
        return ret;
    }

    ret = SSL_AlertReceivedCallback(real_fd, JSSL_SSLFDAlertReceivedCallback, fd_ref);
    if (ret != SECSuccess) {
        return ret;
    }

    ret = SSL_AlertSentCallback(real_fd, JSSL_SSLFDAlertSentCallback, fd_ref);
    return ret;
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_ConfigJSSDefaultCertAuthCallback(JNIEnv *env, jclass clazz,
    jobject fd)
{
    PRFileDesc *real_fd = NULL;

    PR_ASSERT(env != NULL && fd != NULL);
    PR_SetError(0, 0);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return SECFailure;
    }

    return SSL_AuthCertificateHook(real_fd, JSSL_DefaultCertAuthCallback, NULL);
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_ConfigAsyncTrustManagerCertAuthCallback(JNIEnv *env, jclass clazz,
    jobject fd)
{
    PRFileDesc *real_fd = NULL;
    jobject fd_ref = NULL;

    PR_ASSERT(env != NULL && fd != NULL);
    PR_SetError(0, 0);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return SECFailure;
    }

    if (JSS_NSS_getGlobalRef(env, fd, &fd_ref) != PR_SUCCESS) {
        return SECFailure;
    }

    return SSL_AuthCertificateHook(real_fd, JSSL_SSLFDAsyncCertAuthCallback, fd_ref);
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_ConfigSyncTrustManagerCertAuthCallback(JNIEnv *env, jclass clazz,
    jobject fd)
{
    PRFileDesc *real_fd = NULL;
    jobject fd_ref = NULL;

    PR_ASSERT(env != NULL && fd != NULL);
    PR_SetError(0, 0);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return SECFailure;
    }

    if (JSS_NSS_getGlobalRef(env, fd, &fd_ref) != PR_SUCCESS) {
        return SECFailure;
    }

    return SSL_AuthCertificateHook(real_fd, JSSL_SSLFDSyncCertAuthCallback, fd_ref);
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_ConfigAsyncBadCertCallback(JNIEnv *env, jclass clazz,
    jobject fd)
{
    PRFileDesc *real_fd = NULL;
    jobject fd_ref = NULL;

    PR_ASSERT(env != NULL && fd != NULL);
    PR_SetError(0, 0);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return SECFailure;
    }

    if (JSS_NSS_getGlobalRef(env, fd, &fd_ref) != PR_SUCCESS) {
        return SECFailure;
    }

    return SSL_BadCertHook(real_fd, JSSL_SSLFDAsyncBadCertCallback, fd_ref);
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_ConfigSyncBadCertCallback(JNIEnv *env, jclass clazz,
    jobject fd)
{
    PRFileDesc *real_fd = NULL;
    jobject fd_ref = NULL;

    PR_ASSERT(env != NULL && fd != NULL);
    PR_SetError(0, 0);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return SECFailure;
    }

    if (JSS_NSS_getGlobalRef(env, fd, &fd_ref) != PR_SUCCESS) {
        return SECFailure;
    }

    return SSL_BadCertHook(real_fd, JSSL_SSLFDSyncBadCertCallback, fd_ref);
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_AuthCertificateComplete(JNIEnv *env, jclass clazz,
    jobject fd, jint error)
{
    PRFileDesc *real_fd = NULL;

    PR_ASSERT(env != NULL && fd != NULL);
    PR_SetError(0, 0);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return SECFailure;
    }

    return SSL_AuthCertificateComplete(real_fd, error);
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_nss_SSL_RemoveCallbacks(JNIEnv *env, jclass clazz,
    jobject fd)
{
    PRFileDesc *real_fd = NULL;

    PR_ASSERT(env != NULL && fd != NULL);
    PR_SetError(0, 0);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return;
    }

    SSL_AlertReceivedCallback(real_fd, NULL, NULL);
    SSL_AlertSentCallback(real_fd, NULL, NULL);
    SSL_AuthCertificateHook(real_fd, NULL, NULL);
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_EnableHandshakeCallback(JNIEnv *env, jclass clazz,
    jobject fd)
{
    PRFileDesc *real_fd = NULL;
    jobject fd_ref = NULL;

    PR_ASSERT(env != NULL && fd != NULL);
    PR_SetError(0, 0);

    if (JSS_PR_getPRFileDesc(env, fd, &real_fd) != PR_SUCCESS) {
        return SECFailure;
    }

    if (JSS_NSS_getGlobalRef(env, fd, &fd_ref) != PR_SUCCESS) {
        return SECFailure;
    }

    return SSL_HandshakeCallback(real_fd, JSSL_SSLFDHandshakeComplete, fd_ref);
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

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_getSSLEnablePostHandshakeAuth(JNIEnv *env, jclass clazz)
{
    return SSL_ENABLE_POST_HANDSHAKE_AUTH;
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_getSSLEnableRenegotiation(JNIEnv *env, jclass clazz)
{
    return SSL_ENABLE_RENEGOTIATION;
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_getSSLRequireSafeNegotiation(JNIEnv *env, jclass clazz)
{
    return SSL_REQUIRE_SAFE_NEGOTIATION;
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_getSSLRenegotiateNever(JNIEnv *env, jclass clazz)
{
    return SSL_RENEGOTIATE_NEVER;
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_getSSLRenegotiateUnrestricted(JNIEnv *env, jclass clazz)
{
    return SSL_RENEGOTIATE_UNRESTRICTED;
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_getSSLRenegotiateRequiresXtn(JNIEnv *env, jclass clazz)
{
    return SSL_RENEGOTIATE_REQUIRES_XTN;
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_getSSLRenegotiateTransitional(JNIEnv *env, jclass clazz)
{
    return SSL_RENEGOTIATE_TRANSITIONAL;
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_getSSLEnableFallbackSCSV(JNIEnv *env, jclass clazz)
{
    return SSL_ENABLE_FALLBACK_SCSV;
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_getSSLRequireNever(JNIEnv *env, jclass clazz)
{
    return SSL_REQUIRE_NEVER;
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_getSSLRequireAlways(JNIEnv *env, jclass clazz)
{
    return SSL_REQUIRE_ALWAYS;
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_getSSLRequireFirstHandshake(JNIEnv *env, jclass clazz)
{
    return SSL_REQUIRE_FIRST_HANDSHAKE;
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_nss_SSL_getSSLRequireNoError(JNIEnv *env, jclass clazz)
{
    return SSL_REQUIRE_NO_ERROR;
}
