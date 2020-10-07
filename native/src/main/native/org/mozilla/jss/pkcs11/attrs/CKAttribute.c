#include <nspr.h>
#include <nss.h>
#include <pkcs11t.h>
#include <jni.h>

#include "CKAttribute.h"
#include "StaticVoidPointer.h"
#include "NativeEnclosure.h"

#include "_jni/org_mozilla_jss_pkcs11_attrs_CKAClass.h"
#include "_jni/org_mozilla_jss_pkcs11_attrs_CKAKeyType.h"
#include "_jni/org_mozilla_jss_pkcs11_attrs_CKAUsage.h"
#include "_jni/org_mozilla_jss_pkcs11_attrs_CKAValueLen.h"

static const CK_BBOOL JSS_CK_TRUE = CK_TRUE;

PRStatus
JSS_PK11_WrapAttribute(JNIEnv *env, jobject this, void *ptr, size_t ptr_length) {
    jclass this_class;
    jfieldID field_id;
    jobject ptr_object;
    CK_ATTRIBUTE_PTR attr = calloc(1, sizeof(CK_ATTRIBUTE));

    PR_ASSERT(env != NULL && this != NULL && attr != NULL);

    this_class = (*env)->GetObjectClass(env, this);
    if (this_class == NULL) {
        goto failure;
    }

    field_id = (*env)->GetFieldID(env, this_class, "type", "J");
    if (field_id == NULL) {
        goto failure;
    }

    attr->type = (CK_ULONG)((*env)->GetLongField(env, this, field_id));
    attr->pValue = ptr;
    attr->ulValueLen = ptr_length;

    ptr_object = JSS_PR_wrapStaticVoidPointer(env, (void **)&attr);
    if (ptr_object == NULL) {
        goto failure;
    }

    if (JSS_PR_StoreNativeEnclosure(env, this, ptr_object, sizeof(CK_ATTRIBUTE)) != PR_SUCCESS) {
        goto failure;
    }

    return PR_SUCCESS;

failure:
    memset(attr, 0, sizeof(CK_ATTRIBUTE));
    free(attr);
    return PR_FAILURE;
}

PRStatus
JSS_PK11_UnwrapAttribute(JNIEnv *env, jobject this, CK_ATTRIBUTE_PTR *attr) {
    jobject ptr_obj;
    jlong size = 0;

    PR_ASSERT(env != NULL && this != NULL && attr != NULL);

    if (JSS_PR_LoadNativeEnclosure(env, this, &ptr_obj, &size) != PR_SUCCESS) {
        goto failure;
    }

    if (JSS_PR_getStaticVoidRef(env, ptr_obj, (void **)attr) != PR_SUCCESS || *attr == NULL) {
        goto failure;
    }

    if (size != sizeof(CK_ATTRIBUTE)) {
        goto failure;
    }

    return PR_SUCCESS;

failure:
    *attr = NULL;
    return PR_FAILURE;
}

/* ===== CKA_CLASS Attribute ===== */

JNIEXPORT void JNICALL
Java_org_mozilla_jss_pkcs11_attrs_CKAClass_acquireNativeResources(JNIEnv *env, jobject this)
{
    jclass this_class;
    jfieldID field_id;
    CK_ULONG *ptr = calloc(1, sizeof(CK_ULONG));

    PR_ASSERT(env != NULL && this != NULL && ptr != NULL);

    this_class = (*env)->GetObjectClass(env, this);
    if (this_class == NULL) {
        goto failure;
    }

    field_id = (*env)->GetFieldID(env, this_class, "value", "J");
    if (field_id == NULL) {
        goto failure;
    }

    *ptr = (CK_ULONG)((*env)->GetLongField(env, this, field_id));

    if (JSS_PK11_WrapAttribute(env, this, (void *)ptr, sizeof(*ptr)) == PR_FAILURE) {
        goto failure;
    }

    return;

failure:
    memset(ptr, 0, sizeof(*ptr));
    free(ptr);
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_pkcs11_attrs_CKAClass_releaseNativeResources(JNIEnv *env, jobject this)
{
    CK_ATTRIBUTE_PTR attr = NULL;

    if (JSS_PK11_UnwrapAttribute(env, this, &attr) != PR_SUCCESS || attr == NULL) {
        return;
    }

    PR_ASSERT(attr->type == CKA_CLASS);
    PR_ASSERT(attr->pValue != NULL);
    PR_ASSERT(attr->ulValueLen == sizeof(CK_ULONG));

    if (attr->pValue != NULL) {
        memset(attr->pValue, 0, attr->ulValueLen);
        free(attr->pValue);
    }

    memset(attr, 0, sizeof(CK_ATTRIBUTE));
    free(attr);

    return;
}

/* ===== CKA_KEY_TYPE Attribute ===== */

JNIEXPORT void JNICALL
Java_org_mozilla_jss_pkcs11_attrs_CKAKeyType_acquireNativeResources(JNIEnv *env, jobject this)
{
    jclass this_class;
    jfieldID field_id;
    CK_ULONG *ptr = calloc(1, sizeof(CK_ULONG));

    PR_ASSERT(env != NULL && this != NULL && ptr != NULL);

    this_class = (*env)->GetObjectClass(env, this);
    if (this_class == NULL) {
        goto failure;
    }

    field_id = (*env)->GetFieldID(env, this_class, "value", "J");
    if (field_id == NULL) {
        goto failure;
    }

    *ptr = (CK_ULONG)((*env)->GetLongField(env, this, field_id));

    JSS_PK11_WrapAttribute(env, this, (void *)ptr, sizeof(*ptr));

    return;
failure:
    memset(ptr, 0, sizeof(*ptr));
    free(ptr);
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_pkcs11_attrs_CKAKeyType_releaseNativeResources(JNIEnv *env, jobject this)
{
    CK_ATTRIBUTE_PTR attr = NULL;

    if (JSS_PK11_UnwrapAttribute(env, this, &attr) != PR_SUCCESS || attr == NULL) {
        return;
    }

    PR_ASSERT(attr->type == CKA_KEY_TYPE);
    PR_ASSERT(attr->pValue != NULL);
    PR_ASSERT(attr->ulValueLen == sizeof(CK_ULONG));

    if (attr->pValue != NULL) {
        memset(attr->pValue, 0, attr->ulValueLen);
        free(attr->pValue);
    }

    memset(attr, 0, sizeof(CK_ATTRIBUTE));
    free(attr);

    return;
}

/* ===== CKA_{ENCRYPT,DECRYPT,...} Usage Attributes ===== */

JNIEXPORT void JNICALL
Java_org_mozilla_jss_pkcs11_attrs_CKAUsage_acquireNativeResources(JNIEnv *env, jobject this)
{
    JSS_PK11_WrapAttribute(env, this, (void *)&JSS_CK_TRUE, sizeof(JSS_CK_TRUE));
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_pkcs11_attrs_CKAUsage_releaseNativeResources(JNIEnv *env, jobject this)
{
    CK_ATTRIBUTE_PTR attr = NULL;

    if (JSS_PK11_UnwrapAttribute(env, this, &attr) != PR_SUCCESS || attr == NULL) {
        return;
    }

    /* Since the internal pValue member is always a reference to JSS_CK_TRUE,
     * don't free it! Only free the outer CK_ATTRIBUTE pointer. */

    memset(attr, 0, sizeof(CK_ATTRIBUTE));
    free(attr);
}

/* ===== CKA_VALUE_LEN Attribute ===== */

JNIEXPORT void JNICALL
Java_org_mozilla_jss_pkcs11_attrs_CKAValueLen_acquireNativeResources(JNIEnv *env, jobject this)
{
    jclass this_class;
    jfieldID field_id;
    CK_ULONG *ptr = calloc(1, sizeof(CK_ULONG));

    PR_ASSERT(env != NULL && this != NULL && ptr != NULL);

    this_class = (*env)->GetObjectClass(env, this);
    if (this_class == NULL) {
        goto failure;
    }

    field_id = (*env)->GetFieldID(env, this_class, "length", "J");
    if (field_id == NULL) {
        goto failure;
    }

    *ptr = (CK_ULONG)((*env)->GetLongField(env, this, field_id));

    if (JSS_PK11_WrapAttribute(env, this, (void *)ptr, sizeof(*ptr)) == PR_FAILURE) {
        goto failure;
    }

    return;
failure:
    memset(ptr, 0, sizeof(*ptr));
    free(ptr);
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_pkcs11_attrs_CKAValueLen_releaseNativeResources(JNIEnv *env, jobject this)
{
    CK_ATTRIBUTE_PTR attr = NULL;

    if (JSS_PK11_UnwrapAttribute(env, this, &attr) != PR_SUCCESS || attr == NULL) {
        return;
    }

    PR_ASSERT(attr->type == CKA_VALUE_LEN);
    PR_ASSERT(attr->pValue != NULL);
    PR_ASSERT(attr->ulValueLen == sizeof(CK_ULONG));

    if (attr->pValue != NULL) {
        memset(attr->pValue, 0, attr->ulValueLen);
        free(attr->pValue);
    }

    memset(attr, 0, sizeof(CK_ATTRIBUTE));
    free(attr);

    return;
}
