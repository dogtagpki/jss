#include <jni.h>
#include "j_bytebuffer.h"

#pragma once

/* Wrap a j_buffer object into a BufferProxy, freeing the buffer on error. */
jobject JSS_PR_wrapJByteBuffer(JNIEnv *env, j_bytebuffer **buffer);

/* Extract a j_buffer pointer from an instance of a BufferProxy. */
PRStatus JSS_PR_unwrapJByteBuffer(JNIEnv *env, jobject buffer_proxy, j_bytebuffer **buffer);
