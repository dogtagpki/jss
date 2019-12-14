#include <nspr.h>
#include <jni.h>
#include <stdlib.h>

PRStatus
JSS_PR_LoadNativeEnclosure(JNIEnv *env, jobject this, jobject *ptrObj, jlong *ptrSize);

PRStatus
JSS_PR_StoreNativeEnclosure(JNIEnv *env, jobject this, jobject ptrObj, jlong ptrSize);
