#include <jni.h>
#include <nspr.h>
#include <ssl.h>

#pragma once

/* Wrap a NSS SSLVersionRange object into a org.mozilla.jss.ssl.SSLVersionRange object. */
jobject JSS_SSL_wrapVersionRange(JNIEnv *env, SSLVersionRange vrange);

// Not implemented: easier to do in Java
/* Unwrap a org.mozilla.jss.ssl.SSLVersionRange object and return a NSS SSLVersionRange. */
/* PRStatus JSS_SSL_unwrapVersionRange(JNIEnv *env, jobject range_proxy,
    SSLVersionRange *vrange); */
