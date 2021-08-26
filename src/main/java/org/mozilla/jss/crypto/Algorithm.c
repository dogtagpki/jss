/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <seccomon.h>
#include <secoidt.h>
#include <pkcs11t.h>
#include <secmodt.h>
#include <nspr.h>
#include <jni.h>
#include <java_ids.h>
#include <pk11func.h>

#include <jssutil.h>

#include "Algorithm.h"

static PRStatus
getAlgInfo(JNIEnv *env, jobject alg, JSS_AlgInfo *info);

/* Helpers to handle differences in NSS versions. */
#ifndef CKM_AES_CMAC
#define CKM_AES_CMAC CKM_INVALID_MECHANISM
#endif

#ifndef CKM_SP800_108_COUNTER_KDF
/* All added at the same time. */
#define CKM_SP800_108_COUNTER_KDF CKM_INVALID_MECHANISM
#define CKM_SP800_108_FEEDBACK_KDF CKM_INVALID_MECHANISM
#define CKM_SP800_108_DOUBLE_PIPELINE_KDF CKM_INVALID_MECHANISM
#define CKM_NSS_SP800_108_COUNTER_KDF_DERIVE_DATA CKM_INVALID_MECHANISM
#define CKM_NSS_SP800_108_FEEDBACK_KDF_DERIVE_DATA CKM_INVALID_MECHANISM
#define CKM_NSS_SP800_108_DOUBLE_PIPELINE_KDF_DERIVE_DATA CKM_INVALID_MECHANISM
#endif

#define OI(x)                                  \
    {                                          \
        siDEROID, (unsigned char *)x, sizeof x \
    }
#define OD(oid, tag, desc, mech, ext) \
    {                                 \
        OI(oid)                       \
        , tag, desc, mech, ext        \
    }
#define ODN(oid, desc)                                           \
    {                                                            \
        OI(oid)                                                  \
        , 0, desc, CKM_INVALID_MECHANISM, INVALID_CERT_EXTENSION \
    }

#define OIDT static const unsigned char


/* USGov algorithm OID space: { 2 16 840 1 101 } */
#define USGOV 0x60, 0x86, 0x48, 0x01, 0x65
#define NISTALGS USGOV, 3, 4
#define AES NISTALGS, 1

/* AES_KEY_WRAP_KWP oids */

OIDT aes128_KEY_WRAP_KWP[] = { AES, 8 };
OIDT aes192_KEY_WRAP_KWP[] = { AES, 28 };
OIDT aes256_KEY_WRAP_KWP[] = { AES, 48 };

/* ------------------------------------------------------------------- */
static const SECOidData oids[] = {
    /* AES_KEY_WRAP_KWP oids */

    OD(aes128_KEY_WRAP_KWP,0,"AES-128 Key Wrap Kwp", CKM_AES_KEY_WRAP_KWP, INVALID_CERT_EXTENSION),
    OD(aes192_KEY_WRAP_KWP,0,"AES-192 Key Wrap Kwp", CKM_AES_KEY_WRAP_KWP, INVALID_CERT_EXTENSION),
    OD(aes256_KEY_WRAP_KWP,0,"AES-256 Key Wrap Kwp", CKM_AES_KEY_WRAP_KWP, INVALID_CERT_EXTENSION),

};

static const unsigned int numOids = (sizeof oids) / (sizeof oids[0]);

static SECOidTag newOIDTags[3];


/***********************************************************************
**
**  Algorithm indices.  This must be kept in sync with the algorithm
**  tags in the Algorithm class.
**  We only store CKMs as a last resort if there is no corresponding
**  SEC_OID.
**/
JSS_AlgInfo JSS_AlgTable[NUM_ALGS] = {
/* 0 */     {SEC_OID_PKCS1_MD2_WITH_RSA_ENCRYPTION, SEC_OID_TAG},
/* 1 */     {SEC_OID_PKCS1_MD5_WITH_RSA_ENCRYPTION, SEC_OID_TAG},
/* 2 */     {SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION, SEC_OID_TAG},
/* 3 */     {SEC_OID_ANSIX9_DSA_SIGNATURE_WITH_SHA1_DIGEST, SEC_OID_TAG},
/* 4 */     {SEC_OID_PKCS1_RSA_ENCRYPTION, SEC_OID_TAG},
/* 5 */     {CKM_RSA_PKCS_KEY_PAIR_GEN, PK11_MECH},
/* 6 */     {CKM_DSA_KEY_PAIR_GEN, PK11_MECH},
/* 7 */     {SEC_OID_ANSIX9_DSA_SIGNATURE, SEC_OID_TAG},
/* 8 */     {SEC_OID_RC4, SEC_OID_TAG},
/* 9 */     {SEC_OID_DES_ECB, SEC_OID_TAG},
/* 10 */    {SEC_OID_DES_CBC, SEC_OID_TAG},
/* 11 */    {CKM_DES_CBC_PAD, PK11_MECH},
/* 12 */    {CKM_DES3_ECB, PK11_MECH},
/* 13 */    {SEC_OID_DES_EDE3_CBC, SEC_OID_TAG},
/* 14 */    {CKM_DES3_CBC_PAD, PK11_MECH},
/* 15 */    {CKM_DES_KEY_GEN, PK11_MECH},
/* 16 */    {CKM_DES3_KEY_GEN, PK11_MECH},
/* 17 */    {CKM_RC4_KEY_GEN, PK11_MECH},
/* 18 */    {SEC_OID_PKCS5_PBE_WITH_MD2_AND_DES_CBC, SEC_OID_TAG},
/* 19 */    {SEC_OID_PKCS5_PBE_WITH_MD5_AND_DES_CBC, SEC_OID_TAG},
/* 20 */    {SEC_OID_PKCS5_PBE_WITH_SHA1_AND_DES_CBC, SEC_OID_TAG},
/* 21 */    {SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC4, SEC_OID_TAG},
/* 22 */    {SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC4, SEC_OID_TAG},
/* 23 */    {SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_3KEY_TRIPLE_DES_CBC,
                        SEC_OID_TAG},
/* 24 */    {SEC_OID_MD2, SEC_OID_TAG},
/* 25 */    {SEC_OID_MD5, SEC_OID_TAG},
/* 26 */    {SEC_OID_SHA1, SEC_OID_TAG},
/* 27 */    {CKM_SHA_1_HMAC, PK11_MECH},
/* 28 */    {SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC2_CBC, SEC_OID_TAG},
/* 29 */    {SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC, SEC_OID_TAG},
/* 30 */    {SEC_OID_RC2_CBC, SEC_OID_TAG},
/* 31 */    {CKM_PBA_SHA1_WITH_SHA1_HMAC, PK11_MECH},
/* 32 */    {CKM_AES_KEY_GEN, PK11_MECH},
/* 33 */    {CKM_AES_ECB, PK11_MECH},
/* 34 */    {CKM_AES_CBC, PK11_MECH},
/* 35 */    {CKM_AES_CBC_PAD, PK11_MECH},
/* 36 */    {CKM_RC2_CBC_PAD, PK11_MECH},
/* 37 */    {CKM_RC2_KEY_GEN, PK11_MECH},
/* 38 */    {SEC_OID_SHA256, SEC_OID_TAG},
/* 39 */    {SEC_OID_SHA384, SEC_OID_TAG},
/* 40 */    {SEC_OID_SHA512, SEC_OID_TAG},
/* 41 */    {SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION, SEC_OID_TAG},
/* 42 */    {SEC_OID_PKCS1_SHA384_WITH_RSA_ENCRYPTION, SEC_OID_TAG},
/* 43 */    {SEC_OID_PKCS1_SHA512_WITH_RSA_ENCRYPTION, SEC_OID_TAG},
/* 44 */    {SEC_OID_ANSIX962_EC_PUBLIC_KEY, SEC_OID_TAG},
/* 45 */    {SEC_OID_ANSIX962_ECDSA_SHA1_SIGNATURE, SEC_OID_TAG},
/* 46 */    {CKM_EC_KEY_PAIR_GEN, PK11_MECH},
/* 47 */    {SEC_OID_ANSIX962_ECDSA_SHA256_SIGNATURE, SEC_OID_TAG},
/* 48 */    {SEC_OID_ANSIX962_ECDSA_SHA384_SIGNATURE, SEC_OID_TAG},
/* 49 */    {SEC_OID_ANSIX962_ECDSA_SHA512_SIGNATURE, SEC_OID_TAG},
/* 50 */    {SEC_OID_HMAC_SHA256, SEC_OID_TAG},
/* 51 */    {SEC_OID_HMAC_SHA384, SEC_OID_TAG},
/* 52 */    {SEC_OID_HMAC_SHA512, SEC_OID_TAG},
/* 53 */    {SEC_OID_PKCS5_PBKDF2, SEC_OID_TAG},
/* 54 */    {SEC_OID_PKCS5_PBES2, SEC_OID_TAG},
/* 55 */    {SEC_OID_PKCS5_PBMAC1, SEC_OID_TAG},
/* 56 */    {SEC_OID_ANSIX962_ECDSA_SIGNATURE_SPECIFIED_DIGEST, SEC_OID_TAG},
/* 57 */    {CKM_NSS_AES_KEY_WRAP, PK11_MECH},
/* 58 */    {CKM_NSS_AES_KEY_WRAP_PAD, PK11_MECH},
/* 59 */    {SEC_OID_AES_128_ECB, SEC_OID_TAG},
/* 60 */    {SEC_OID_AES_128_CBC, SEC_OID_TAG},
/* 61 */    {SEC_OID_AES_192_ECB, SEC_OID_TAG},
/* 62 */    {SEC_OID_AES_192_CBC, SEC_OID_TAG},
/* 63 */    {SEC_OID_AES_256_ECB, SEC_OID_TAG},
/* 64 */    {SEC_OID_AES_256_CBC, SEC_OID_TAG},
/* the CKM_AES_KEY_WRAP_* have different defs than CKM_NSS_AES_KEY_WRAP_*  */
/* 65 */    {CKM_AES_KEY_WRAP, PK11_MECH},
/* 66 */    {CKM_AES_KEY_WRAP_PAD, PK11_MECH},
/* 67 */    {CKM_SHA256_HMAC, PK11_MECH},
/* 68 */    {CKM_SHA384_HMAC, PK11_MECH},
/* 69 */    {CKM_SHA512_HMAC, PK11_MECH},

/* CKM_AES_CMAC is new to NSS; some implementations might not yet have it. */
/* 70 */    {CKM_AES_CMAC, PK11_MECH},

/* CKM_GENERIC_SECRET_KEY_GEN stub for additional keys. */
/* 71 */    {CKM_GENERIC_SECRET_KEY_GEN, PK11_MECH},

/* CKM_SP800_108_* and CKM_NSS_SP800_108_*_DERIVE_DATA are new to NSS; some
 * implementations might not yet have it. */
/* 72 */    {CKM_SP800_108_COUNTER_KDF, PK11_MECH},
/* 73 */    {CKM_SP800_108_FEEDBACK_KDF, PK11_MECH},
/* 74 */    {CKM_SP800_108_DOUBLE_PIPELINE_KDF, PK11_MECH},
/* 75 */    {CKM_NSS_SP800_108_COUNTER_KDF_DERIVE_DATA, PK11_MECH},
/* 76 */    {CKM_NSS_SP800_108_FEEDBACK_KDF_DERIVE_DATA, PK11_MECH},
/* 77 */    {CKM_NSS_SP800_108_DOUBLE_PIPELINE_KDF_DERIVE_DATA, PK11_MECH},
/* 78 */    {SEC_OID_PKCS1_RSA_PSS_SIGNATURE, SEC_OID_TAG},
/* 79 */    {CKM_RSA_PKCS_OAEP, PK11_MECH},
/* 80 */    {CKM_AES_KEY_WRAP_KWP, PK11_MECH},
/* 81 */    {SEC_OID_AES_128_KEY_WRAP_KWP, SEC_OID_TAG},
/* 82 */    {SEC_OID_AES_192_KEY_WRAP_KWP, SEC_OID_TAG},
/* 83 */    {SEC_OID_AES_256_KEY_WRAP_KWP, SEC_OID_TAG},


/* REMEMBER TO UPDATE NUM_ALGS!!! (in Algorithm.h) */
};

/* Fetch and register an oid if it hasn't been done already */
void
JSS_cert_fetchOID(SECOidTag *data, const SECOidData *src)
{
    if (*data == SEC_OID_UNKNOWN) {
        /* AddEntry does the right thing if someone else has already
         * added the oid. (that is return that oid tag) */
        *data = SECOID_AddEntry(src);
    }
}

SECStatus
JSS_RegisterDynamicOids(void)
{
    unsigned int i;
    SECStatus rv = SECSuccess;

    for (i = 0; i < numOids; ++i) {
        SECOidTag tag = SECOID_AddEntry(&oids[i]);
        if (tag == SEC_OID_UNKNOWN) {
            rv = SECFailure;
        } else {
            newOIDTags[i] = tag;
        }
    }
    return rv;
}


/***********************************************************************
 *
 * J S S _ g e t P K 1 1 M e c h F r o m A l g
 *
 * INPUTS
 *      alg
 *          An org.mozilla.jss.Algorithm object. Must not be NULL.
 * RETURNS
 *          CK_MECHANISM_TYPE corresponding to this algorithm, or
 *          CKM_INVALID_MECHANISM if none exists.
 */
CK_MECHANISM_TYPE
JSS_getPK11MechFromAlg(JNIEnv *env, jobject alg)
{
    JSS_AlgInfo info;

    if( getAlgInfo(env, alg, &info) != PR_SUCCESS) {
        return CKM_INVALID_MECHANISM;
    }
    if( info.type == PK11_MECH ) {
        return (CK_MECHANISM_TYPE) info.val;
    } else {
        PR_ASSERT( info.type == SEC_OID_TAG );
        return PK11_AlgtagToMechanism( (SECOidTag) info.val);
    }
}

/***********************************************************************
 *
 * J S S _ g e t O i d T a g F r o m A l g
 *
 * INPUTS
 *      alg
 *          An org.mozilla.jss.Algorithm object. Must not be NULL.
 * RETURNS
 *      SECOidTag corresponding to this algorithm, or SEC_OID_UNKNOWN
 *      if none was found.
 */
SECOidTag
JSS_getOidTagFromAlg(JNIEnv *env, jobject alg)
{
    JSS_AlgInfo info;

    if( getAlgInfo(env, alg, &info) != PR_SUCCESS) {
        return SEC_OID_UNKNOWN;
    }
    if( info.type == SEC_OID_TAG ) {
        return (SECOidTag) info.val;
    } else {
        PR_ASSERT( info.type == PK11_MECH );
        /* We only store things as PK11 mechanisms as a last resort if
         * there is no corresponding sec oid tag. */
        return SEC_OID_UNKNOWN;
    }
}

/***********************************************************************
 *
 * J S S _ g e t A l g I n d e x
 *
 * INPUTS
 *      alg
 *          An org.mozilla.jss.Algorithm object. Must not be NULL.
 * RETURNS
 *      The index obtained from the algorithm, or -1 if an exception was
 *      thrown.
 */
static jint
getAlgIndex(JNIEnv *env, jobject alg)
{
    jclass algClass;
    jint index=-1;
    jfieldID indexField;

    PR_ASSERT(env!=NULL && alg!=NULL);

    algClass = (*env)->GetObjectClass(env, alg);

#ifdef DEBUG
    /* Make sure this really is an Algorithm. */
    {
    jclass realClass = ((*env)->FindClass(env, ALGORITHM_CLASS_NAME));
    PR_ASSERT( (*env)->IsInstanceOf(env, alg, realClass) );
    }
#endif

    indexField = (*env)->GetFieldID(
                                    env,
                                    algClass,
                                    OID_INDEX_FIELD_NAME,
                                    OID_INDEX_FIELD_SIG);
    if(indexField==NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    index = (*env)->GetIntField(env, alg, indexField);
    PR_ASSERT( (index >= 0) && (index < NUM_ALGS) );

finish:
    return index;
}

/***********************************************************************
 *
 * J S S _ g e t E n u m F r o m A l g
 *
 * INPUTS
 *      alg
 *          An org.mozilla.jss.Algorithm object. Must not be NULL.
 * OUTPUTS
 *      info
 *          Pointer to a JSS_AlgInfo which will get the information about
 *          this algorithm, if it is found.  Must not be NULL.
 * RETURNS
 *      PR_SUCCESS if the enum was found, otherwise PR_FAILURE.
 */
static PRStatus
getAlgInfo(JNIEnv *env, jobject alg, JSS_AlgInfo *info)
{
    jint index;
    PRStatus status = PR_FAILURE;

    PR_ASSERT(env!=NULL && alg!=NULL && info!=NULL);

    index = getAlgIndex(env, alg);
    if( index == -1 ) {
        goto finish;
    }
    *info = JSS_AlgTable[index];
    status = PR_SUCCESS;

finish:
    return status;
}

/***********************************************************************
 *
 * EncryptionAlgorithm.getIVLength
 *
 */
JNIEXPORT jint JNICALL
Java_org_mozilla_jss_crypto_EncryptionAlgorithm_getIVLength
    (JNIEnv *env, jobject this)
{
    CK_MECHANISM_TYPE mech;

    mech = JSS_getPK11MechFromAlg(env, this);

    if( mech == CKM_INVALID_MECHANISM ) {
        PR_ASSERT(PR_FALSE);
        return 0;
    } else {
        return PK11_GetIVLength(mech);
    }
}

/*
 * This must be synchronized with SymmetricKey.Usage
 */
CK_ULONG JSS_symkeyUsage[] = {
    CKA_ENCRYPT,        /* 0 */
    CKA_DECRYPT,        /* 1 */
    CKA_WRAP,           /* 2 */
    CKA_UNWRAP,         /* 3 */
    CKA_SIGN,           /* 4 */
    CKA_VERIFY,         /* 5 */
    0UL
};
