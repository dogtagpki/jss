#include <nss.h>
#include <pk11pub.h>
#include <pkcs11n.h>
#include <pkcs11t.h>
#include <jni.h>

#include "_jni/org_mozilla_jss_crypto_JSSOAEPParameterSpec.h"

#include "jssutil.h"
#include "java_ids.h"
#include "jss_exceptions.h"
#include "pk11util.h"

#include "NativeEnclosure.h"
#include "StaticVoidPointer.h"

PRStatus
oaep_GetHashAlg(JNIEnv *env, jobject this, jclass this_class, CK_MECHANISM_TYPE *ret)
{
    jfieldID field_id = NULL;

    field_id = (*env)->GetFieldID(env, this_class, "hashAlg", "J");
    if (field_id == NULL) {
        return PR_FAILURE;
    }

    *ret = (*env)->GetLongField(env, this, field_id);
    return PR_SUCCESS;
}

PRStatus
oaep_GetMGFType(JNIEnv *env, jobject this, jclass this_class, CK_RSA_PKCS_MGF_TYPE *ret)
{
    jfieldID field_id = NULL;

    field_id = (*env)->GetFieldID(env, this_class, "mgf", "J");
    if (field_id == NULL) {
        return PR_FAILURE;
    }

    *ret = (*env)->GetLongField(env, this, field_id);
    return PR_SUCCESS;
}

PRStatus
oaep_GetSpecifiedSourceData(JNIEnv *env, jobject this, jclass this_class, CK_VOID_PTR *ret, CK_ULONG *ret_len)
{
    jfieldID field_id = NULL;
    jbyteArray data = NULL;

    field_id = (*env)->GetFieldID(env, this_class, "sourceData", "[B");
    if (field_id == NULL) {
        return PR_FAILURE;
    }

    data = (*env)->GetObjectField(env, this, field_id);
    if (data == NULL) {
        *ret = NULL;
        *ret_len = 0;
        return PR_SUCCESS;
    }

    if (!JSS_FromByteArray(env, data, (uint8_t **)ret, ret_len)) {
        return PR_FAILURE;
    }

    return PR_SUCCESS;
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_crypto_JSSOAEPParameterSpec_acquireNativeResources(JNIEnv *env, jobject this)
{
    jclass this_class = NULL;

    CK_MECHANISM_TYPE hashAlg;
    CK_RSA_PKCS_MGF_TYPE mgf;
    CK_RSA_PKCS_OAEP_SOURCE_TYPE source = CKZ_DATA_SPECIFIED;
    CK_VOID_PTR pSourceData = NULL;
    CK_ULONG ulSourceDataLen = 0;
    CK_RSA_PKCS_OAEP_PARAMS_PTR oaep_params = NULL;

    jobject params_obj;

    this_class = (*env)->GetObjectClass(env, this);
    if (this_class == NULL) {
        return;
    }

    if (oaep_GetHashAlg(env, this, this_class, &hashAlg) != PR_SUCCESS) {
        return;
    }

    if (oaep_GetMGFType(env, this, this_class, &mgf) != PR_SUCCESS) {
        return;
    }

    /* Here on down, we need to go to failure on error, to free our
     * allocated data. */

    if (oaep_GetSpecifiedSourceData(env, this, this_class, &pSourceData, &ulSourceDataLen) != PR_SUCCESS) {
        goto failure;
    }

    oaep_params = calloc(1, sizeof(CK_RSA_PKCS_OAEP_PARAMS));
    oaep_params->hashAlg = hashAlg;
    oaep_params->mgf = mgf;
    oaep_params->source = source;
    oaep_params->pSourceData = pSourceData;
    oaep_params->ulSourceDataLen = ulSourceDataLen;

    params_obj = JSS_PR_wrapStaticVoidPointer(env, (void **)&oaep_params);
    if (params_obj == NULL) {
        goto failure;
    }

    if (JSS_PR_StoreNativeEnclosure(env, this, params_obj, sizeof(CK_RSA_PKCS_OAEP_PARAMS)) != PR_SUCCESS) {
        goto failure;
    }

    return;

failure:
    free(pSourceData);
    free(oaep_params);
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_crypto_JSSOAEPParameterSpec_releaseNativeResources(JNIEnv *env, jobject this)
{
    jobject ptr_object = NULL;

    CK_RSA_PKCS_OAEP_PARAMS_PTR oaep_params = NULL;
    jlong params_length;

    PR_ASSERT(env != NULL && this != NULL);

    if (JSS_PR_LoadNativeEnclosure(env, this, &ptr_object, &params_length) != PR_SUCCESS) {
        return;
    }

    if (JSS_PR_getStaticVoidRef(env, ptr_object, (void **)&oaep_params) != PR_SUCCESS || oaep_params == NULL) {
        return;
    }

    PR_ASSERT(params_length == sizeof(CK_RSA_PKCS_OAEP_PARAMS));

    if (oaep_params->ulSourceDataLen != 0 && oaep_params->pSourceData != NULL) {
        memset(oaep_params->pSourceData, 0, sizeof(CK_VOID_PTR) * oaep_params->ulSourceDataLen);
        free(oaep_params->pSourceData);
    }

    memset(oaep_params, 0, sizeof(CK_RSA_PKCS_OAEP_PARAMS));
    free(oaep_params);
}
