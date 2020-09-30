#include <nspr.h>
#include <jni.h>

#include "java_ids.h"
#include "NativeEnclosure.h"

PRStatus
JSS_PR_LoadNativeEnclosure(JNIEnv *env, jobject this, jobject *ptrObj, jlong *ptrSize)
{
    jclass this_class = NULL;
    jfieldID field_id = NULL;

    PR_ASSERT(env != NULL && this != NULL && ptrObj != NULL && ptrSize != NULL);

    this_class = (*env)->GetObjectClass(env, this);
    if (this_class == NULL) {
        return PR_FAILURE;
    }

    field_id = (*env)->GetFieldID(env, this_class, "mPointer", "L" NATIVE_PROXY_CLASS_NAME ";");
    if (field_id == NULL) {
        return PR_FAILURE;
    }

    *ptrObj = (*env)->GetObjectField(env, this, field_id);
    if (ptrObj == NULL) {
        return PR_FAILURE;
    }

    field_id = (*env)->GetFieldID(env, this_class, "mPointerSize", "J");
    if (field_id == NULL) {
        return PR_FAILURE;
    }

    *ptrSize = (*env)->GetLongField(env, this, field_id);

    return PR_SUCCESS;
}

PRStatus
JSS_PR_StoreNativeEnclosure(JNIEnv *env, jobject this, jobject ptrObj, jlong ptrSize)
{
    jclass this_class = NULL;
    jfieldID field_id = NULL;

    PR_ASSERT(env != NULL && this != NULL && ptrObj != NULL);

    this_class = (*env)->GetObjectClass(env, this);
    if (this_class == NULL) {
        return PR_FAILURE;
    }

    field_id = (*env)->GetFieldID(env, this_class, "mPointer", "L" NATIVE_PROXY_CLASS_NAME ";");
    if (field_id == NULL) {
        return PR_FAILURE;
    }

    (*env)->SetObjectField(env, this, field_id, ptrObj);

    field_id = (*env)->GetFieldID(env, this_class, "mPointerSize", "J");
    if (field_id == NULL) {
        return PR_FAILURE;
    }

    (*env)->SetLongField(env, this, field_id, ptrSize);

    return PR_SUCCESS;
}

