#include <nspr.h>
#include <nss.h>
#include <ssl.h>
#include <jni.h>
#include <pk11pub.h>

#include "_jni/org_mozilla_jss_ssl_SSLCipher.h"
#include "jssconfig.h"

/* Copied from NSS's ssl3con.c. */
static const CK_MECHANISM_TYPE auth_alg_defs[] = {
    CKM_INVALID_MECHANISM, /* ssl_auth_null */
    CKM_RSA_PKCS,          /* ssl_auth_rsa_decrypt */
    CKM_DSA, /* ? _SHA1 */ /* ssl_auth_dsa */
    CKM_INVALID_MECHANISM, /* ssl_auth_kea (unused) */
    CKM_ECDSA,             /* ssl_auth_ecdsa */
    CKM_ECDH1_DERIVE,      /* ssl_auth_ecdh_rsa */
    CKM_ECDH1_DERIVE,      /* ssl_auth_ecdh_ecdsa */
    CKM_RSA_PKCS,          /* ssl_auth_rsa_sign */
    CKM_RSA_PKCS_PSS,      /* ssl_auth_rsa_pss */
    CKM_NSS_HKDF_SHA256,   /* ssl_auth_psk (just check for HKDF) */
    CKM_INVALID_MECHANISM  /* ssl_auth_tls13_any */
};
PR_STATIC_ASSERT(PR_ARRAY_SIZE(auth_alg_defs) == ssl_auth_size);

/* Copied from NSS's ssl3con.c. */
static const CK_MECHANISM_TYPE kea_alg_defs[] = {
    CKM_INVALID_MECHANISM, /* ssl_kea_null */
    CKM_RSA_PKCS,          /* ssl_kea_rsa */
    CKM_DH_PKCS_DERIVE,    /* ssl_kea_dh */
    CKM_INVALID_MECHANISM, /* ssl_kea_fortezza (unused) */
    CKM_ECDH1_DERIVE,      /* ssl_kea_ecdh */
    CKM_ECDH1_DERIVE,      /* ssl_kea_ecdh_psk */
    CKM_DH_PKCS_DERIVE,    /* ssl_kea_dh_psk */
    CKM_INVALID_MECHANISM, /* ssl_kea_tls13_any */
};
PR_STATIC_ASSERT(PR_ARRAY_SIZE(kea_alg_defs) == ssl_kea_size);

#ifdef HAVE_NSS_CIPHER_SUITE_INFO_KDFHASH
/* Not present in ssl3con.c. */
static const CK_MECHANISM_TYPE hash_alg_defs[] = {
    CKM_INVALID_MECHANISM, /* ssl_hash_none */
    CKM_MD5,               /* ssl_hash_md5 */
    CKM_SHA_1,             /* ssl_hash_sha1 */
    CKM_SHA224,            /* ssl_hash_sha224 */
    CKM_SHA256,            /* ssl_hash_sha256 */
    CKM_SHA384,            /* ssl_hash_sha384 */
    CKM_SHA512,            /* ssl_hash_sha512 */
};
#endif

JNIEXPORT jboolean JNICALL
Java_org_mozilla_jss_ssl_SSLCipher_checkSupportedStatus(JNIEnv *env, jclass clazz, jint cipher_suite)
{
    PRInt32 allowed;
    SSLCipherSuiteInfo info = { 0 };

    /* Fetch information about whether or not this cipher is allowed by local
     * policy. */
    if (SSL_CipherPolicyGet(cipher_suite, &allowed) != SECSuccess) {
        /* When the previous call fails, it means that the specified cipher
         * suite wasn't found; calls to enable it will also fail. Mark it as
         * unsupported. */
        return JNI_FALSE;
    }

    if (allowed != SSL_ALLOWED) {
        /* If the cipher suite isn't allowed by policy, reject it early. */
        return JNI_FALSE;
    }

    /* Fetch extended information about this particular cipher suite. */
    if (SSL_GetCipherSuiteInfo(cipher_suite, &info, sizeof(info)) != SECSuccess) {
        /* Since we know the cipher suite is good (because the call to
         * SSL_CipherPolicyGet(...) succeeded), we know that this is because
         * the size of SSLCipherSuiteInfo in the version of NSS that we
         * were compiled with exceeds the size of the SSLCipherSuiteInfo
         * struct available to NSS at runtime.
         *
         * This happens *only* when the version of NSS we were compiled with
         * is *newer* than what is on the system.
         *
         * This is a "soft" failure and means that we have to rely only on
         * cipher policy to tell if this cipher is supported. Since it was
         * allowed, return JNI_TRUE here. */
        return JNI_TRUE;
    }

    /* Our NSS DB or application could've configured FIPS mode explicitly,
     * even though the system might not be in FIPS mode. In that case,
     * explicitly check that this allowed cipher is available in FIPS mode. */
    if (PK11_IsFIPS() && info.isFIPS == 0) {
        return JNI_FALSE;
    }

    /* Our last checks are to make sure that, for all related mechanisms, we
     * have a token with this function. This is similar to the code in NSS's
     * ssl3_config_match_init(...). Note that this doesn't finish the work
     * of that function (by checking that the certificate matches the cipher
     * suite). */
    if (info.authType != ssl_auth_tls13_any &&
            info.authType != ssl_auth_null &&
            !PK11_TokenExists(auth_alg_defs[info.authType])) {
        return JNI_FALSE;
    }

    if (info.keaType != ssl_kea_null &&
            info.keaType != ssl_kea_tls13_any &&
            !PK11_TokenExists(kea_alg_defs[info.keaType])) {
        return JNI_FALSE;
    }

    /* Only check if NSS >= 3.43 or if this feature was backported. Note that
     * when this condition holds at compile time, and we're executing under
     * an older NSS version, we'd have exited due to the check in
     * SSL_GetCipherSuiteInfo(...). That means that the value read here is
     * always correct. */
#ifdef HAVE_NSS_CIPHER_SUITE_INFO_KDFHASH
    if (info.kdfHash != ssl_hash_none &&
            !PK11_TokenExists(hash_alg_defs[info.kdfHash])) {
        return JNI_FALSE;
    }
#endif

    return JNI_TRUE;
}
