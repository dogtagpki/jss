#include <nss.h>
#include <pk11pub.h>
#include <pkcs11n.h>
#include <pkcs11t.h>
#include <jni.h>

#include "_jni/org_mozilla_jss_crypto_KBKDFByteArrayParam.h"
#include "_jni/org_mozilla_jss_crypto_KBKDFCounterParams.h"
#include "_jni/org_mozilla_jss_crypto_KBKDFDerivedKey.h"
#include "_jni/org_mozilla_jss_crypto_KBKDFDKMLengthParam.h"
#include "_jni/org_mozilla_jss_crypto_KBKDFFeedbackParams.h"
#include "_jni/org_mozilla_jss_crypto_KBKDFIterationVariableParam.h"
#include "_jni/org_mozilla_jss_crypto_KBKDFOptionalCounterParam.h"
#include "_jni/org_mozilla_jss_crypto_KBKDFPipelineParams.h"

#include "jssutil.h"
#include "java_ids.h"
#include "jss_exceptions.h"
#include "pk11util.h"

#include "CKAttribute.h"
#include "NativeEnclosure.h"
#include "StaticVoidPointer.h"

#ifndef CKM_SP800_108_COUNTER_KDF

#define __NOT_IMPLEMENTED__(name) JNIEXPORT void JNICALL \
name(JNIEnv *env, jobject this) \
{ \
    JSS_throwMsg(env, UNSUPPORTED_OPERATION_EXCEPTION, \
    "KBKDF Operations aren't supported by the version of NSS that JSS was compiled against."); \
}

__NOT_IMPLEMENTED__(Java_org_mozilla_jss_crypto_KBKDFByteArrayParam_acquireNativeResourcesInternal);
__NOT_IMPLEMENTED__(Java_org_mozilla_jss_crypto_KBKDFByteArrayParam_releaseNativeResourcesInternal);
__NOT_IMPLEMENTED__(Java_org_mozilla_jss_crypto_KBKDFCounterParams_acquireNativeResourcesInternal);
__NOT_IMPLEMENTED__(Java_org_mozilla_jss_crypto_KBKDFCounterParams_releaseNativeResourcesInternal);
__NOT_IMPLEMENTED__(Java_org_mozilla_jss_crypto_KBKDFDerivedKey_acquireNativeResourcesInternal);
__NOT_IMPLEMENTED__(Java_org_mozilla_jss_crypto_KBKDFDerivedKey_releaseNativeResourcesInternal);
__NOT_IMPLEMENTED__(Java_org_mozilla_jss_crypto_KBKDFDKMLengthParam_acquireNativeResources);
__NOT_IMPLEMENTED__(Java_org_mozilla_jss_crypto_KBKDFDKMLengthParam_releaseNativeResources);
__NOT_IMPLEMENTED__(Java_org_mozilla_jss_crypto_KBKDFFeedbackParams_acquireNativeResourcesInternal);
__NOT_IMPLEMENTED__(Java_org_mozilla_jss_crypto_KBKDFFeedbackParams_releaseNativeResourcesInternal);
__NOT_IMPLEMENTED__(Java_org_mozilla_jss_crypto_KBKDFIterationVariableParam_acquireNativeResources);
__NOT_IMPLEMENTED__(Java_org_mozilla_jss_crypto_KBKDFIterationVariableParam_releaseNativeResources);
__NOT_IMPLEMENTED__(Java_org_mozilla_jss_crypto_KBKDFOptionalCounterParam_acquireNativeResources);
__NOT_IMPLEMENTED__(Java_org_mozilla_jss_crypto_KBKDFOptionalCounterParam_releaseNativeResources);
__NOT_IMPLEMENTED__(Java_org_mozilla_jss_crypto_KBKDFPipelineParams_acquireNativeResourcesInternal);
__NOT_IMPLEMENTED__(Java_org_mozilla_jss_crypto_KBKDFPipelineParams_releaseNativeResourcesInternal);

JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_crypto_KBKDFDerivedKey_getKeyFromHandle(JNIEnv *env, jobject this, jobject parentKey, jlong mech, jboolean temporary)
{
    JSS_throwMsg(env, UNSUPPORTED_OPERATION_EXCEPTION,
    "KBKDF Operations aren't supported by the version of NSS that JSS was compiled against.");
    return NULL;
}

#else

/* ===== KBKDF Data Parameter Wrappers ===== */

PRStatus
kbkdf_WrapDataParam(JNIEnv *env, jobject this, jclass *this_class, void *ptr, size_t ptr_length)
{
    jfieldID field_id = NULL;
    size_t param_length = sizeof(CK_PRF_DATA_PARAM);
    CK_PRF_DATA_PARAM_PTR param = calloc(1, param_length);
    jobject ptr_object = NULL;

    PR_ASSERT(env != NULL && this != NULL && this_class != NULL && param != NULL);

    if (*this_class == NULL) {
        *this_class = (*env)->GetObjectClass(env, this);
        if (*this_class == NULL) {
            goto failure;
        }
    }

    field_id = (*env)->GetFieldID(env, *this_class, "type", "J");
    if (field_id == NULL) {
        goto failure;
    }

    param->type = (CK_PRF_DATA_TYPE)((*env)->GetLongField(env, this, field_id));
    param->pValue = ptr;
    param->ulValueLen = ptr_length;

    ptr_object = JSS_PR_wrapStaticVoidPointer(env, (void **)&param);
    if (ptr_object == NULL) {
        goto failure;
    }

    if (JSS_PR_StoreNativeEnclosure(env, this, ptr_object, param_length) != PR_SUCCESS) {
        goto failure;
    }

    return PR_SUCCESS;

failure:
    memset(param, 0, param_length);
    free(param);

    return PR_FAILURE;
}

PRStatus
kbkdf_UnwrapDataParam(JNIEnv *env, jobject this, CK_PRF_DATA_PARAM_PTR *param, size_t *param_length)
{
    jobject ptr_object = NULL;
    jlong size = 0;

    PR_ASSERT(env != NULL && this != NULL && param != NULL && param_length != NULL);

    if (JSS_PR_LoadNativeEnclosure(env, this, &ptr_object, &size) != PR_SUCCESS) {
        goto failure;
    }

    if (JSS_PR_getStaticVoidRef(env, ptr_object, (void **)param) != PR_SUCCESS || *param == NULL) {
        goto failure;
    }

    *param_length = size;

    return PR_SUCCESS;

failure:
    *param = NULL;
    *param_length = 0;

    return PR_FAILURE;
}

/* ===== KBKDF Byte Array Parameter ===== */

JNIEXPORT void JNICALL
Java_org_mozilla_jss_crypto_KBKDFByteArrayParam_acquireNativeResourcesInternal(JNIEnv *env, jobject this)
{
    jclass this_class = NULL;
    jfieldID field_id;
    jbyteArray this_data;

    uint8_t *array = NULL;
    size_t length = 0;

    PR_ASSERT(env != NULL && this != NULL);

    this_class = (*env)->GetObjectClass(env, this);
    if (this_class == NULL) {
        return;
    }

    field_id = (*env)->GetFieldID(env, this_class, "data", "[B");
    if (field_id == NULL) {
        return;
    }

    this_data = (*env)->GetObjectField(env, this, field_id);
    if (this_data == NULL) {
        return;
    }

    if (!JSS_FromByteArray(env, this_data, &array, &length)) {
        return;
    }

    /* From here on out, we need to zero and free our copy of the array before
     * returning from error cases. */

    if (kbkdf_WrapDataParam(env, this, &this_class, array, length) != PR_SUCCESS) {
        goto failure;
    }

    return;

failure:
    memset(array, 0, length);
    free(array);
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_crypto_KBKDFByteArrayParam_releaseNativeResourcesInternal(JNIEnv *env, jobject this)
{
    CK_PRF_DATA_PARAM_PTR param;
    size_t param_size = 0;

    if (kbkdf_UnwrapDataParam(env, this, &param, &param_size) != PR_SUCCESS) {
        return;
    }

    PR_ASSERT(param_size = sizeof(CK_PRF_DATA_PARAM));
    PR_ASSERT(param->type == CK_SP800_108_BYTE_ARRAY);

    if (param->pValue != NULL) {
        memset(param->pValue, 0, param->ulValueLen);
    }
    free(param->pValue);

    if (param != NULL) {
        memset(param, 0, param_size);
    }
    free(param);
}

/* ===== KBKDF Interation Variable Parameter ===== */

JNIEXPORT void JNICALL
Java_org_mozilla_jss_crypto_KBKDFIterationVariableParam_acquireNativeResources(JNIEnv *env, jobject this)
{
    jclass this_class = NULL;
    jfieldID field_id;

    jboolean littleEndian = JNI_FALSE;
    jlong widthInBits = 0;

    CK_SP800_108_COUNTER_FORMAT_PTR data = NULL;
    size_t data_length = 0;

    this_class = (*env)->GetObjectClass(env, this);
    if (this_class == NULL) {
        return;
    }

    field_id = (*env)->GetFieldID(env, this_class, "littleEndian", "Z");
    if (field_id == NULL) {
        return;
    }

    littleEndian = (*env)->GetBooleanField(env, this, field_id);

    field_id = (*env)->GetFieldID(env, this_class, "widthInBits", "J");
    if (field_id == NULL) {
        return;
    }

    widthInBits = (*env)->GetLongField(env, this, field_id);
    if (widthInBits == 0) {
        return;
    }

    if (widthInBits >= 8) {
        data_length = sizeof(CK_SP800_108_COUNTER_FORMAT);
        data = calloc(1, data_length);

        if (data == NULL) {
            return;
        }

        /* From here on out we need to goto failure, freeing data on failure. */

        data->bLittleEndian = (littleEndian == JNI_TRUE) ? CK_TRUE : CK_FALSE;
        data->ulWidthInBits = (CK_ULONG)widthInBits;
    }

    if (kbkdf_WrapDataParam(env, this, &this_class, data, data_length) != PR_SUCCESS) {
        goto failure;
    }

    return;

failure:
    memset(data, 0, sizeof(CK_SP800_108_COUNTER_FORMAT));
    free(data);
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_crypto_KBKDFIterationVariableParam_releaseNativeResources(JNIEnv *env, jobject this)
{
    CK_PRF_DATA_PARAM_PTR param;
    size_t param_size = 0;

    if (kbkdf_UnwrapDataParam(env, this, &param, &param_size) != PR_SUCCESS) {
        return;
    }

    PR_ASSERT(param_size = sizeof(CK_PRF_DATA_PARAM));
    PR_ASSERT(param->type == CK_SP800_108_ITERATION_VARIABLE);

    if (param->pValue != NULL) {
        PR_ASSERT(param->ulValueLen == sizeof(CK_SP800_108_COUNTER_FORMAT));

        memset(param->pValue, 0, param->ulValueLen);
        free(param->pValue);
    }

    if (param != NULL) {
        memset(param, 0, param_size);
        free(param);
    }
}

/* ===== KBKDF Optional Counter Parameter ===== */

JNIEXPORT void JNICALL
Java_org_mozilla_jss_crypto_KBKDFOptionalCounterParam_acquireNativeResources(JNIEnv *env, jobject this)
{
    jclass this_class = NULL;
    jfieldID field_id;

    jboolean littleEndian = JNI_FALSE;
    jlong widthInBits = 0;

    CK_SP800_108_COUNTER_FORMAT_PTR data = NULL;
    size_t data_length = 0;

    this_class = (*env)->GetObjectClass(env, this);
    if (this_class == NULL) {
        return;
    }

    field_id = (*env)->GetFieldID(env, this_class, "littleEndian", "Z");
    if (field_id == NULL) {
        return;
    }

    littleEndian = (*env)->GetBooleanField(env, this, field_id);

    field_id = (*env)->GetFieldID(env, this_class, "widthInBits", "J");
    if (field_id == NULL) {
        return;
    }

    widthInBits = (*env)->GetLongField(env, this, field_id);
    if (widthInBits == 0) {
        return;
    }

    data_length = sizeof(CK_SP800_108_COUNTER_FORMAT);
    data = calloc(1, data_length);

    if (data == NULL) {
        return;
    }

    /* From here on out we need to goto failure, freeing data on failure. */

    data->bLittleEndian = (littleEndian == JNI_TRUE) ? CK_TRUE : CK_FALSE;
    data->ulWidthInBits = (CK_ULONG)widthInBits;

    if (kbkdf_WrapDataParam(env, this, &this_class, data, data_length) != PR_SUCCESS) {
        goto failure;
    }

    return;

failure:
    memset(data, 0, sizeof(CK_SP800_108_COUNTER_FORMAT));
    free(data);
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_crypto_KBKDFOptionalCounterParam_releaseNativeResources(JNIEnv *env, jobject this)
{
    CK_PRF_DATA_PARAM_PTR param;
    size_t param_size = 0;

    if (kbkdf_UnwrapDataParam(env, this, &param, &param_size) != PR_SUCCESS) {
        return;
    }

    PR_ASSERT(param_size = sizeof(CK_PRF_DATA_PARAM));
    PR_ASSERT(param->type == CK_SP800_108_OPTIONAL_COUNTER);
    PR_ASSERT(param->ulValueLen == sizeof(CK_SP800_108_COUNTER_FORMAT));

    if (param->pValue != NULL) {
        memset(param->pValue, 0, param->ulValueLen);
        free(param->pValue);
    }

    if (param != NULL) {
        memset(param, 0, param_size);
        free(param);
    }
}

/* ===== KBKDF DKM Length Parameter ===== */

JNIEXPORT void JNICALL
Java_org_mozilla_jss_crypto_KBKDFDKMLengthParam_acquireNativeResources(JNIEnv *env, jobject this)
{
    jclass this_class = NULL;
    jfieldID field_id;

    jlong method = 0;
    jboolean littleEndian = JNI_FALSE;
    jlong widthInBits = 0;

    CK_SP800_108_DKM_LENGTH_FORMAT_PTR data = NULL;
    size_t data_length = 0;

    this_class = (*env)->GetObjectClass(env, this);
    if (this_class == NULL) {
        return;
    }

    field_id = (*env)->GetFieldID(env, this_class, "lengthMethod", "J");
    if (field_id == NULL) {
        return;
    }

    method = (*env)->GetLongField(env, this, field_id);

    field_id = (*env)->GetFieldID(env, this_class, "littleEndian", "Z");
    if (field_id == NULL) {
        return;
    }

    littleEndian = (*env)->GetBooleanField(env, this, field_id);

    field_id = (*env)->GetFieldID(env, this_class, "widthInBits", "J");
    if (field_id == NULL) {
        return;
    }

    widthInBits = (*env)->GetLongField(env, this, field_id);
    if (widthInBits == 0) {
        return;
    }

    data_length = sizeof(CK_SP800_108_DKM_LENGTH_FORMAT);
    data = calloc(1, data_length);

    if (data == NULL) {
        return;
    }

    /* From here on out we need to goto failure, freeing data on failure. */

    data->dkmLengthMethod = (CK_SP800_108_DKM_LENGTH_METHOD)method;
    data->bLittleEndian = (littleEndian == JNI_TRUE) ? CK_TRUE : CK_FALSE;
    data->ulWidthInBits = (CK_ULONG)widthInBits;

    if (kbkdf_WrapDataParam(env, this, &this_class, data, data_length) != PR_SUCCESS) {
        goto failure;
    }

    return;

failure:
    memset(data, 0, sizeof(CK_SP800_108_DKM_LENGTH_FORMAT));
    free(data);
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_crypto_KBKDFDKMLengthParam_releaseNativeResources(JNIEnv *env, jobject this)
{
    CK_PRF_DATA_PARAM_PTR param;
    size_t param_size = 0;

    if (kbkdf_UnwrapDataParam(env, this, &param, &param_size) != PR_SUCCESS) {
        return;
    }

    PR_ASSERT(param_size = sizeof(CK_PRF_DATA_PARAM));
    PR_ASSERT(param->type == CK_SP800_108_DKM_LENGTH);
    PR_ASSERT(param->ulValueLen == sizeof(CK_SP800_108_DKM_LENGTH_FORMAT));

    if (param->pValue != NULL) {
        memset(param->pValue, 0, param->ulValueLen);
        free(param->pValue);
    }

    if (param != NULL) {
        memset(param, 0, param_size);
        free(param);
    }
}

/* ===== KBKDF Derived Keys ===== */

    JNIEXPORT void JNICALL
Java_org_mozilla_jss_crypto_KBKDFDerivedKey_acquireNativeResourcesInternal(JNIEnv *env, jobject this)
{
    jclass this_class = NULL;
    jfieldID field_id = NULL;
    CK_ATTRIBUTE_PTR attrs = NULL;
    CK_ULONG num_attrs = 0;
    CK_OBJECT_HANDLE_PTR key_handle = NULL;
    CK_DERIVED_KEY_PTR ptr = NULL;

    jobject ptr_obj = NULL;
    jobjectArray attrs_array = NULL;

    this_class = (*env)->GetObjectClass(env, this);
    if (this_class == NULL) {
        goto failure;
    }

    field_id = (*env)->GetFieldID(env, this_class, "attrs", "[L" CK_ATTRIBUTE_CLASS_NAME ";");
    if (field_id == NULL) {
        goto failure;
    }

    attrs_array = (*env)->GetObjectField(env, this, field_id);
    if (attrs_array == NULL) {
        goto failure;
    }

    num_attrs = (*env)->GetArrayLength(env, attrs_array);
    attrs = calloc(num_attrs, sizeof(CK_ATTRIBUTE));

    for (size_t offset = 0; offset < num_attrs; offset++) {
        jobject this_attr_obj;
        CK_ATTRIBUTE_PTR attr;

        this_attr_obj = (*env)->GetObjectArrayElement(env, attrs_array, offset);
        if (this_attr_obj == NULL) {
            goto failure;
        }

        if (JSS_PK11_UnwrapAttribute(env, this_attr_obj, &attr) != PR_SUCCESS) {
            goto failure;
        }

        attrs[offset] = *attr;
    }

    key_handle = calloc(1, sizeof(CK_OBJECT_HANDLE));
    if (key_handle == NULL) {
        goto failure;
    }

    ptr = calloc(1, sizeof(CK_DERIVED_KEY));
    if (ptr == NULL) {
        goto failure;
    }

    ptr->pTemplate = attrs;
    ptr->ulAttributeCount = num_attrs;
    ptr->phKey = key_handle;

    ptr_obj = JSS_PR_wrapStaticVoidPointer(env, (void **)&ptr);
    if (ptr_obj == NULL) {
        goto failure;
    }

    if (JSS_PR_StoreNativeEnclosure(env, this, ptr_obj, sizeof(CK_DERIVED_KEY)) != PR_SUCCESS) {
        goto failure;
    }

    return;

failure:
    if (attrs != NULL) {
        memset(attrs, 0, num_attrs * sizeof(CK_ATTRIBUTE));
        free(attrs);
    }

    if (key_handle != NULL) {
        memset(key_handle, 0, sizeof(CK_OBJECT_HANDLE));
        free(key_handle);
    }

    if (ptr != NULL) {
        memset(ptr, 0, sizeof(CK_DERIVED_KEY));
        free(ptr);
    }
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_crypto_KBKDFDerivedKey_releaseNativeResourcesInternal(JNIEnv *env, jobject this)
{
    jclass this_class = NULL;
    jfieldID field_id = NULL;
    jobject ptr_obj = NULL;
    jlong size = 0;
    CK_DERIVED_KEY_PTR ptr = NULL;

    if (JSS_PR_LoadNativeEnclosure(env, this, &ptr_obj, &size) != PR_SUCCESS) {
        return;
    }

    if (JSS_PR_getStaticVoidRef(env, ptr_obj, (void **)&ptr) != PR_SUCCESS || ptr == NULL) {
        return;
    }

    PR_ASSERT(size == sizeof(CK_DERIVED_KEY));

    /* Save off the derived key, if/when possible, before freeing the
     * underlying CK_DERIVED_KEY struct. */

    if (ptr->phKey == NULL) {
        goto free;
    }

    this_class = (*env)->GetObjectClass(env, this);
    if (this_class == NULL) {
        goto free;
    }

    field_id = (*env)->GetFieldID(env, this_class, "handle", "J");
    if (field_id == NULL) {
        goto free;
    }

    (*env)->SetLongField(env, this, field_id, *(ptr->phKey));

free:
    if (ptr->pTemplate != NULL) {
        memset(ptr->pTemplate, 0, ptr->ulAttributeCount * sizeof(CK_ATTRIBUTE));
        free(ptr->pTemplate);
    }

    if (ptr->phKey != NULL) {
        memset(ptr->phKey, 0, sizeof(CK_OBJECT_HANDLE));
        free(ptr->phKey);
    }

    memset(ptr, 0, sizeof(CK_DERIVED_KEY));
    free(ptr);
}

JNIEXPORT jobject JNICALL
Java_org_mozilla_jss_crypto_KBKDFDerivedKey_getKeyFromHandle(JNIEnv *env, jobject this, jobject parentKey, jlong mech, jboolean temporary)
{
    jclass this_class = NULL;
    jfieldID field_id = NULL;
    CK_OBJECT_HANDLE handle = 0;
    PK11SymKey *parent = NULL;
    PK11SlotInfo *slot = NULL;
    PK11SymKey *key = NULL;
    PRBool is_perm = (temporary == JNI_TRUE) ? PR_FALSE : PR_TRUE;

    this_class = (*env)->GetObjectClass(env, this);
    if (this_class == NULL) {
        return NULL;
    }

    field_id = (*env)->GetFieldID(env, this_class, "handle", "J");
    if (field_id == NULL) {
        return NULL;
    }

    handle = (CK_OBJECT_HANDLE)((*env)->GetLongField(env, this, field_id));

    if (JSS_PK11_getSymKeyPtr(env, parentKey, &parent) != PR_SUCCESS || parent == NULL) {
        return NULL;
    }

    slot = PK11_GetSlotFromKey(parent);
    PK11_FreeSlot(slot);

    key = PK11_SymKeyFromHandle(slot, parent, PK11_OriginDerive, mech,
                                handle, is_perm, NULL);

    return JSS_PK11_wrapSymKey(env, &key);
}

/* ===== KBKDF Parameter Helpers ===== */

PRStatus
kbkdf_GetPRFType(JNIEnv *env, jobject this, jclass this_class, CK_SP800_108_PRF_TYPE *prf_type)
{
    jfieldID field_id = NULL;

    field_id = (*env)->GetFieldID(env, this_class, "prf", "J");
    if (field_id == NULL) {
        return PR_FAILURE;
    }

    *prf_type = (*env)->GetLongField(env, this, field_id);
    return PR_SUCCESS;
}

PRStatus
kbkdf_GetDataParameters(JNIEnv *env, jobject this, jclass this_class, CK_ULONG *num_data_params, CK_PRF_DATA_PARAM_PTR *data_params)
{
    jfieldID field_id = NULL;
    jobjectArray params_array = NULL;

    field_id = (*env)->GetFieldID(env, this_class, "params", "[L" KBKDF_DATA_PARAMETER_CLASS_NAME ";");
    if (field_id == NULL) {
        return PR_FAILURE;
    }

    params_array = (*env)->GetObjectField(env, this, field_id);
    if (params_array == NULL) {
        return PR_FAILURE;
    }

    *num_data_params = (*env)->GetArrayLength(env, params_array);
    *data_params = calloc(*num_data_params, sizeof(CK_PRF_DATA_PARAM));

    for (size_t offset = 0; offset < *num_data_params; offset++) {
        jobject this_param_object = NULL;
        CK_PRF_DATA_PARAM_PTR this_param = NULL;
        size_t this_param_size = 0;

        this_param_object = (*env)->GetObjectArrayElement(env, params_array, offset);
        if (this_param_object == NULL) {
            return PR_FAILURE;
        }

        if (kbkdf_UnwrapDataParam(env, this_param_object, &this_param, &this_param_size) != PR_SUCCESS) {
            return PR_FAILURE;
        }

        PR_ASSERT(this_param_size == sizeof(CK_PRF_DATA_PARAM));

        (*data_params)[offset] = *this_param;
    }

    return PR_SUCCESS;
}

PRStatus
kbkdf_GetAdditionalDerivedKeys(JNIEnv *env, jobject this, jclass this_class, CK_ULONG *num_additional_keys, CK_DERIVED_KEY_PTR *additional_keys)
{
    jfieldID field_id = NULL;
    jobjectArray keys_array = NULL;

    field_id = (*env)->GetFieldID(env, this_class, "additional_keys", "[L" KBKDF_DERIVED_KEY_CLASS_NAME ";");
    if (field_id == NULL) {
        return PR_FAILURE;
    }

    keys_array = (*env)->GetObjectField(env, this, field_id);
    if (keys_array == NULL) {
        *num_additional_keys = 0;
        *additional_keys = NULL;
        return PR_SUCCESS;
    }

    *num_additional_keys = (*env)->GetArrayLength(env, keys_array);
    *additional_keys = calloc(*num_additional_keys, sizeof(CK_DERIVED_KEY));

    for (size_t offset = 0; offset < *num_additional_keys; offset++) {
        jobject this_key_object = NULL;
        CK_DERIVED_KEY_PTR this_key = NULL;
        jobject this_key_ptr = NULL;
        jlong this_key_size = 0;

        this_key_object = (*env)->GetObjectArrayElement(env, keys_array, offset);
        if (this_key_object == NULL) {
            return PR_FAILURE;
        }

        if (JSS_PR_LoadNativeEnclosure(env, this_key_object, &this_key_ptr, &this_key_size) != PR_SUCCESS) {
            return PR_FAILURE;
        }

        if (JSS_PR_getStaticVoidRef(env, this_key_ptr, (void **)&this_key) != PR_SUCCESS || this_key == NULL) {
            return PR_FAILURE;
        }

        PR_ASSERT(this_key_size == sizeof(CK_DERIVED_KEY));

        (*additional_keys)[offset] = *this_key;
    }

    return PR_SUCCESS;
}

PRStatus
kbkdf_GetInitialValue(JNIEnv *env, jobject this, jclass this_class, CK_ULONG *initial_value_length, CK_BYTE_PTR *initial_value)
{
    jfieldID field_id = NULL;
    jobjectArray iv_array = NULL;

    field_id = (*env)->GetFieldID(env, this_class, "initial_value", "[B");
    if (field_id == NULL) {
        return PR_FAILURE;
    }

    iv_array = (*env)->GetObjectField(env, this, field_id);
    if (iv_array == NULL) {
        *initial_value_length = 0;
        *initial_value = NULL;
        return PR_SUCCESS;
    }

    if (!JSS_FromByteArray(env, iv_array, initial_value, initial_value_length)) {
        return PR_FAILURE;
    }

    return PR_SUCCESS;
}

/* ===== KBKDF Counter Parameters ===== */

JNIEXPORT void JNICALL
Java_org_mozilla_jss_crypto_KBKDFCounterParams_acquireNativeResourcesInternal(JNIEnv *env, jobject this)
{
    jclass this_class = NULL;

    CK_SP800_108_PRF_TYPE prf_type = CKM_INVALID_MECHANISM;
    CK_ULONG num_data_params = 0;
    CK_PRF_DATA_PARAM_PTR data_params = NULL;
    CK_ULONG num_additional_keys = 0;
    CK_DERIVED_KEY_PTR additional_keys = NULL;
    CK_SP800_108_KDF_PARAMS_PTR kdf_params = NULL;

    jobject params_obj;

    this_class = (*env)->GetObjectClass(env, this);
    if (this_class == NULL) {
        return;
    }

    /* Handle PRF Type. */
    if (kbkdf_GetPRFType(env, this, this_class, &prf_type) != PR_SUCCESS) {
        goto failure;
    }

    /* Handle Data Parameters. */
    if (kbkdf_GetDataParameters(env, this, this_class, &num_data_params, &data_params) != PR_SUCCESS) {
        goto failure;
    }

    /* Handle Additional Derived Keys. */
    if (kbkdf_GetAdditionalDerivedKeys(env, this, this_class, &num_additional_keys, &additional_keys) != PR_SUCCESS) {
        goto failure;
    }

    /* Place the values in the actual KDF params struct. */
    kdf_params = calloc(1, sizeof(CK_SP800_108_KDF_PARAMS));

    kdf_params->prfType = prf_type;
    kdf_params->ulNumberOfDataParams = num_data_params;
    kdf_params->pDataParams = data_params;
    kdf_params->ulAdditionalDerivedKeys = num_additional_keys;
    kdf_params->pAdditionalDerivedKeys = additional_keys;

    /* Place it back into this NativeEnclosure. */
    params_obj = JSS_PR_wrapStaticVoidPointer(env, (void **)&kdf_params);
    if (params_obj == NULL) {
        goto failure;
    }

    if (JSS_PR_StoreNativeEnclosure(env, this, params_obj, sizeof(CK_SP800_108_KDF_PARAMS)) != PR_SUCCESS) {
        goto failure;
    }

    return;

failure:
    if (data_params != NULL) {
        memset(data_params, 0, sizeof(CK_PRF_DATA_PARAM) * num_data_params);
        free(data_params);
    }

    if (additional_keys != NULL) {
        memset(additional_keys, 0, sizeof(CK_DERIVED_KEY) * num_additional_keys);
        free(additional_keys);
    }

    if (kdf_params != NULL) {
        memset(kdf_params, 0, sizeof(CK_SP800_108_KDF_PARAMS));
        free(kdf_params);
    }
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_crypto_KBKDFCounterParams_releaseNativeResourcesInternal(JNIEnv *env, jobject this)
{
    jobject ptr_object = NULL;

    CK_SP800_108_KDF_PARAMS_PTR kdf_params = NULL;
    jlong params_length;

    PR_ASSERT(env != NULL && this != NULL);

    if (JSS_PR_LoadNativeEnclosure(env, this, &ptr_object, &params_length) != PR_SUCCESS) {
        return;
    }

    if (JSS_PR_getStaticVoidRef(env, ptr_object, (void **)&kdf_params) != PR_SUCCESS || kdf_params == NULL) {
        return;
    }

    PR_ASSERT(params_length == sizeof(CK_SP800_108_KDF_PARAMS));

    if (kdf_params->ulNumberOfDataParams != 0 && kdf_params->pDataParams != NULL) {
        memset(kdf_params->pDataParams, 0, sizeof(CK_PRF_DATA_PARAM) * kdf_params->ulNumberOfDataParams);
        free(kdf_params->pDataParams);
    }

    if (kdf_params->ulAdditionalDerivedKeys != 0 && kdf_params->pAdditionalDerivedKeys != NULL) {
        memset(kdf_params->pAdditionalDerivedKeys, 0, sizeof(CK_DERIVED_KEY) * kdf_params->ulAdditionalDerivedKeys);
        free(kdf_params->pAdditionalDerivedKeys);
    }

    memset(kdf_params, 0, params_length);
    free(kdf_params);
}

/* ===== KBKDF Feedback Parameters ===== */

JNIEXPORT void JNICALL
Java_org_mozilla_jss_crypto_KBKDFFeedbackParams_acquireNativeResourcesInternal(JNIEnv *env, jobject this)
{
    jclass this_class = NULL;

    CK_SP800_108_PRF_TYPE prf_type = CKM_INVALID_MECHANISM;
    CK_ULONG num_data_params = 0;
    CK_PRF_DATA_PARAM_PTR data_params = NULL;
    CK_ULONG num_additional_keys = 0;
    CK_DERIVED_KEY_PTR additional_keys = NULL;
    CK_ULONG initial_value_length = 0;
    CK_BYTE_PTR initial_value = NULL;
    CK_SP800_108_FEEDBACK_KDF_PARAMS_PTR kdf_params = NULL;

    jobject params_obj;

    this_class = (*env)->GetObjectClass(env, this);
    if (this_class == NULL) {
        return;
    }

    /* Handle PRF Type. */
    if (kbkdf_GetPRFType(env, this, this_class, &prf_type) != PR_SUCCESS) {
        goto failure;
    }

    /* Handle Data Parameters. */
    if (kbkdf_GetDataParameters(env, this, this_class, &num_data_params, &data_params) != PR_SUCCESS) {
        goto failure;
    }

    /* Handle Additional Derived Keys. */
    if (kbkdf_GetAdditionalDerivedKeys(env, this, this_class, &num_additional_keys, &additional_keys) != PR_SUCCESS) {
        goto failure;
    }

    /* Handle Initial Value. */
    if (kbkdf_GetInitialValue(env, this, this_class, &initial_value_length, &initial_value) != PR_SUCCESS) {
        goto failure;
    }

    /* Place the values in the actual KDF params struct. */
    kdf_params = calloc(1, sizeof(CK_SP800_108_FEEDBACK_KDF_PARAMS));

    kdf_params->prfType = prf_type;
    kdf_params->ulNumberOfDataParams = num_data_params;
    kdf_params->pDataParams = data_params;
    kdf_params->ulAdditionalDerivedKeys = num_additional_keys;
    kdf_params->pAdditionalDerivedKeys = additional_keys;
    kdf_params->ulIVLen = initial_value_length;
    kdf_params->pIV = initial_value;

    /* Place it back into this NativeEnclosure. */
    params_obj = JSS_PR_wrapStaticVoidPointer(env, (void **)&kdf_params);
    if (params_obj == NULL) {
        goto failure;
    }

    if (JSS_PR_StoreNativeEnclosure(env, this, params_obj, sizeof(CK_SP800_108_FEEDBACK_KDF_PARAMS)) != PR_SUCCESS) {
        goto failure;
    }

    return;

failure:
    if (data_params != NULL) {
        memset(data_params, 0, sizeof(CK_PRF_DATA_PARAM) * num_data_params);
        free(data_params);
    }

    if (additional_keys != NULL) {
        memset(additional_keys, 0, sizeof(CK_DERIVED_KEY) * num_additional_keys);
        free(additional_keys);
    }

    if (initial_value != NULL) {
        memset(initial_value, 0, sizeof(CK_BYTE) * initial_value_length);
        free(initial_value);
    }

    if (kdf_params != NULL) {
        memset(kdf_params, 0, sizeof(CK_SP800_108_FEEDBACK_KDF_PARAMS));
        free(kdf_params);
    }
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_crypto_KBKDFFeedbackParams_releaseNativeResourcesInternal(JNIEnv *env, jobject this)
{
    jobject ptr_object = NULL;

    CK_SP800_108_FEEDBACK_KDF_PARAMS_PTR kdf_params = NULL;
    jlong params_length;

    PR_ASSERT(env != NULL && this != NULL);

    if (JSS_PR_LoadNativeEnclosure(env, this, &ptr_object, &params_length) != PR_SUCCESS) {
        return;
    }

    if (JSS_PR_getStaticVoidRef(env, ptr_object, (void **)&kdf_params) != PR_SUCCESS || kdf_params == NULL) {
        return;
    }

    PR_ASSERT(params_length == sizeof(CK_SP800_108_FEEDBACK_KDF_PARAMS));

    if (kdf_params->ulNumberOfDataParams != 0 && kdf_params->pDataParams != NULL) {
        memset(kdf_params->pDataParams, 0, sizeof(CK_PRF_DATA_PARAM) * kdf_params->ulNumberOfDataParams);
        free(kdf_params->pDataParams);
    }

    if (kdf_params->ulIVLen != 0 && kdf_params->pIV != NULL) {
        memset(kdf_params->pIV, 0, sizeof(CK_BYTE) * kdf_params->ulIVLen);
        free(kdf_params->pIV);
    }

    if (kdf_params->ulAdditionalDerivedKeys != 0 && kdf_params->pAdditionalDerivedKeys != NULL) {
        memset(kdf_params->pAdditionalDerivedKeys, 0, sizeof(CK_DERIVED_KEY) * kdf_params->ulAdditionalDerivedKeys);
        free(kdf_params->pAdditionalDerivedKeys);
    }

    memset(kdf_params, 0, params_length);
    free(kdf_params);
}

/* ===== KBKDF Double Pipeline Parameters ===== */


JNIEXPORT void JNICALL
Java_org_mozilla_jss_crypto_KBKDFPipelineParams_acquireNativeResourcesInternal(JNIEnv *env, jobject this)
{
    /* Counter and Double Pipeline modes have the same parameter struct.
     * This allows us to implement this call via the corresponding call for
     * Counter mode. */

    Java_org_mozilla_jss_crypto_KBKDFCounterParams_acquireNativeResourcesInternal(env, this);
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_crypto_KBKDFPipelineParams_releaseNativeResourcesInternal(JNIEnv *env, jobject this)
{
    /* Counter and Double Pipeline modes have the same parameter struct.
     * This allows us to implement this call via the corresponding call for
     * Counter mode. */

    Java_org_mozilla_jss_crypto_KBKDFCounterParams_releaseNativeResourcesInternal(env, this);
}

#endif
