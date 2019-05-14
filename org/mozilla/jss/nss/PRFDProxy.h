#include <nspr.h>
#include <jni.h>

#pragma once

/* Wrap a C/NSPR PRFileDesc into a Java PRFDProxy, closing the fd on error. */
jobject JSS_PR_wrapPRFDProxy(JNIEnv *env, PRFileDesc **fd);

/* Extract the C/NSPR PRFileDesc from an instance of a Java PRFDProxy. */
PRStatus JSS_PR_getPRFileDesc(JNIEnv *env, jobject prfd_proxy, PRFileDesc **fd);
