/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* This file does not contain native methods of NativeProxy; rather, it
 * provides utility functions for using NativeProxys in C code */

#include <jni.h>
#include <nspr.h>
#include "nativeUtil.h"

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
JSS_getPtrFromProxy(JNIEnv *env, jobject nativeProxy, void **ptr)
{
    jclass nativeProxyClass;
    jfieldID byteArrayField;
    jbyteArray byteArray;
    int size;

    PR_ASSERT(env!=NULL && nativeProxy != NULL && ptr != NULL);

    nativeProxyClass = (*env)->FindClass(env, "org/mozilla/jss/util/NativeProxy");
    if(nativeProxyClass == NULL) {
        ASSERT_OUTOFMEM(env);
        return PR_FAILURE;
    }

#ifdef DEBUG
    /* make sure what we got was really a NativeProxy object */
    PR_ASSERT( (*env)->IsInstanceOf(env, nativeProxy, nativeProxyClass) );
#endif

    byteArrayField = (*env)->GetFieldID(env, nativeProxyClass, "mPointer",
        "[B");
    if(byteArrayField==NULL) {
        ASSERT_OUTOFMEM(env);
        return PR_FAILURE;
    }

    byteArray = (jbyteArray) (*env)->GetObjectField(env, nativeProxy,
                        byteArrayField);
    PR_ASSERT(byteArray != NULL);

    size = sizeof(*ptr);
    PR_ASSERT((*env)->GetArrayLength(env, byteArray) == size);
    (*env)->GetByteArrayRegion(env, byteArray, 0, size, (void*)ptr);
    if( (*env)->ExceptionOccurred(env) ) {
        PR_ASSERT(PR_FALSE);
        return PR_FAILURE;
    } else {
        return PR_SUCCESS;
    }
}

/*
 * Turn a C pointer into a Java byte array. The byte array can be passed
 * into a NativeProxy constructor.
 *
 * Returns a byte array containing the pointer, or NULL if an exception
 * was thrown.
 */
jbyteArray
JSS_ptrToByteArray(JNIEnv *env, void *ptr)
{
    jbyteArray byteArray;

    /* Construct byte array from the pointer */
    byteArray = (*env)->NewByteArray(env, sizeof(ptr));
    if(byteArray==NULL) {
        PR_ASSERT( (*env)->ExceptionOccurred(env) != NULL);
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, byteArray, 0, sizeof(ptr), (jbyte*)&ptr);
    if((*env)->ExceptionOccurred(env) != NULL) {
        PR_ASSERT(PR_FALSE);
        return NULL;
    }
    return byteArray;
}
