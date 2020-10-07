#include <nspr.h>
#include <jni.h>

jobject
JSS_PR_wrapStaticVoidPointer(JNIEnv *env, void **ref);

PRStatus
JSS_PR_getStaticVoidRef(JNIEnv *env, jobject ref_proxy, void **ref);
