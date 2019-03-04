#include <cert.h>
#include <jni.h>

#pragma once

jobject JSS_wrapCERTCertificate(JNIEnv *env, CERTCertificate **cert);
PRStatus JSS_unwrapCERTCertificate(JNIEnv *env, jobject cert_proxy, CERTCertificate **cert);
