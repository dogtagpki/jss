#include <nspr.h>
#include <jni.h>

PRStatus
JSS_PK11_WrapAttribute(JNIEnv *env, jobject this, void *ptr, size_t ptr_length);

PRStatus
JSS_PK11_UnwrapAttribute(JNIEnv *env, jobject this, CK_ATTRIBUTE_PTR *attr);
