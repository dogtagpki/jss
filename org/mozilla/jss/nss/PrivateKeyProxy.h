#include <cert.h>
#include <jni.h>

#pragma once

jobject JSS_wrapSECKEYPrivateKey(JNIEnv *env, SECKEYPrivateKey **key);
PRStatus JSS_PR_unwrapSECKEYPrivateKey(JNIEnv *env, jobject key_proxy, SECKEYPrivateKey **key);
