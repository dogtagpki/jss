/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
#ifndef NATIVE_PROXY_H
#define NATIVE_PROXY_H

/* Need to include these headers before this one:
#include <jni.h>
#include <prtypes.h>
*/

PR_BEGIN_EXTERN_C

/*
 * Given a NativeProxy, extract the pointer and store it at the given
 * address.
 *
 * nativeProxy: a JNI reference to a NativeProxy.
 * ptr: address of a void* that will receive the pointer extracted from
 *      the NativeProxy.
 * Returns: PR_SUCCESS on success, PR_FAILURE if an exception was thrown.
 *
 * Example:
 *  DataStructure *recovered;
 *  jobject proxy;
 *  JNIEnv *env;
 *  [...]
 *  if(JSS_getPtrFromProxy(env, proxy, (void**)&recovered) != PR_SUCCESS) {
 *      return;  // exception was thrown!
 *  }
 */
PRStatus
JSS_getPtrFromProxy(JNIEnv *env, jobject nativeProxy, void **ptr);

/*
 * Turn a C pointer into a Java byte array. The byte array can be passed
 * into a NativeProxy constructor.
 *
 * Returns a byte array containing the pointer, or NULL if an exception
 * was thrown.
 */
jbyteArray
JSS_ptrToByteArray(JNIEnv *env, void *ptr);

PR_END_EXTERN_C

#endif
