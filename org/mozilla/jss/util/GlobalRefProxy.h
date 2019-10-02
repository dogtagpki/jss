#include <nspr.h>
#include <nss.h>
#include <jni.h>

#pragma once

jobject JSS_PR_wrapGlobalRef(JNIEnv *env, jobject *ref);

PRStatus JSS_PR_getGlobalRef(JNIEnv *env, jobject ref_proxy, jobject *ref);
