#include <nspr.h>
#include <jni.h>

#pragma once

jobject JSS_PR_wrapPRFDProxy(JNIEnv *env, PRFileDesc **fd);
PRStatus JSS_PR_getPRFileDesc(JNIEnv *env, jobject prfd_proxy, PRFileDesc **fd);
