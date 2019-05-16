#include <jni.h>
#include "buffer.h"

#pragma once

/* Wrap a j_buffer object into a BufferProxy, freeing the buffer on error. */
jobject JSS_PR_wrapJBuffer(JNIEnv *env, j_buffer **buffer);

/* Extract a j_buffer pointer from an instance of a BufferProxy. */
PRStatus JSS_PR_unwrapJBuffer(JNIEnv *env, jobject buffer_proxy, j_buffer **buffer);
