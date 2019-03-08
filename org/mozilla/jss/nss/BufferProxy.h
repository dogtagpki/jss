#include <jni.h>
#include "buffer.h"

#pragma once

jobject JSS_PR_wrapJBuffer(JNIEnv *env, j_buffer **buffer);
PRStatus JSS_PR_unwrapJBuffer(JNIEnv *env, jobject buffer_proxy, j_buffer **buffer);
