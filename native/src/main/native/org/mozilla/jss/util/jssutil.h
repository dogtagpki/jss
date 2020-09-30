/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
#include <stdbool.h>

#include <certt.h>
#include <nspr.h>
#include <jni.h>
#include <secitem.h>

#ifndef JSS_NATIVE_UTIL_H
#define JSS_NATIVE_UTIL_H

/* The following #defines are used to suppress undesired compiler warnings
 * that have been deemed inappropriate.
 *
 * IMPORTANT:  These are ONLY used on an "as-needed" basis!
 */
#ifdef __GNUC__
#define FUNCTION_MAY_NOT_BE_USED __attribute__ ((unused))
#define VARIABLE_MAY_NOT_BE_USED __attribute__ ((unused))
#else
#define FUNCTION_MAY_NOT_BE_USED
#define VARIABLE_MAY_NOT_BE_USED
#endif

PR_BEGIN_EXTERN_C

/**** NSPR private thread functions ****/
/*
PRThread* PR_AttachThread(PRThreadType type,
                                     PRThreadPriority priority,
                     PRThreadStack *stack);

void PR_DetachThread(void);
*/
#define PR_AttachThread(a, b, c)  ((PRThread*)1)
#define PR_DetachThread()

/* defined in CryptoManager.c */
extern JavaVM *JSS_javaVM;

/***********************************************************************
 * J S S _ t h r o w M s g
 *
 * Throw an exception in native code.  You should return right after
 * calling this function.
 *
 * throwableClassName is the name of the throwable you are throwing in
 * JNI class name format (xxx/xx/xxx/xxx). It must not be NULL.
 *
 * message is the message parameter of the throwable. It must not be NULL.
 * If you don't have a message, call JSS_nativeThrow.
 *
 * Example:
 *      JSS_nativeThrowMsg(env, "java/lang/IllegalArgumentException",
 *          "Bogus argument, you ninny");
 *      return -1;
 */
void
JSS_throwMsg(JNIEnv *env, const char *throwableClassName, const char *message);

#define JSS_nativeThrowMsg JSS_throwMsg


/***********************************************************************
 * J S S _ t h r o w
 *
 * Throw an exception in native code.  You should return right after
 * calling this function.
 *
 * throwableClassName is the name of the throwable you are throwing in
 * JNI class name format (xxx/xx/xxx/xxx). It must not be NULL.
 *
 * Example:
 *      JSS_nativeThrow(env, "java/lang/IllegalArgumentException");
 *      return -1;
 */
void
JSS_throw(JNIEnv *env, char *throwableClassName);

#define JSS_nativeThrow JSS_throw

/***********************************************************************
 * A S S E R T _ O U T O F M E M
 *
 * In most JNI calls that throw Exceptions, OutOfMemoryError is the only
 * one that doesn't indicate a bug in the code.  If a JNI function throws
 * an exception (or returns an unexpected NULL), you can call this to 
 * PR_ASSERT that it is due to an OutOfMemory condition. It takes a JNIEnv*,
 * which better not be NULL.
 */
void
JSS_assertOutOfMem(JNIEnv *env);

#ifdef DEBUG
#define ASSERT_OUTOFMEM(env)  JSS_assertOutOfMem(env)
#else
#define ASSERT_OUTOFMEM(env)
#endif

/***********************************************************************
**
** J S S _ g e t P t r F r o m P r o x y
**
** Given a NativeProxy, extract the pointer and store it at the given
** address.
**
** nativeProxy: a JNI reference to a NativeProxy.
** ptr: address of a void* that will receive the pointer extracted from
**      the NativeProxy.
** Returns: PR_SUCCESS on success, PR_FAILURE if an exception was thrown.
**
** Example:
**  DataStructure *recovered;
**  jobject proxy;
**  JNIEnv *env;
**  [...]
**  if(JSS_getPtrFromProxy(env, proxy, (void**)&recovered) != PR_SUCCESS) {
**      return;  // exception was thrown!
**  }
*/
PRStatus
JSS_getPtrFromProxy(JNIEnv *env, jobject nativeProxy, void **ptr);

/***********************************************************************
**
** J S S _ c l e a r P t r F r o m P r o x y
**
** Given a NativeProxy, clear the value of the pointer stored in it. This
** helps to ensure that a double free doesn't occur.
**
** Returns: PR_SUCCESS on success, PR_FAILURE if an exception was thrown.
*/
PRStatus
JSS_clearPtrFromProxy(JNIEnv *env, jobject nativeProxy);

/***********************************************************************
**
** J S S _ g e t P t r F r o m P r o x y O w n e r
**
** Given an object which contains a NativeProxy, extract the pointer
** from the NativeProxy and store it at the given address.
**
** proxyOwner: an object which contains a NativeProxy member.
** proxyFieldName: the name of the NativeProxy member.
** proxyFieldSig: the signature of the NativeProxy member.
** ptr: address of a void* that will receive the extract pointer.
** Returns: PR_SUCCESS for success, PR_FAILURE if an exception was thrown.
**
** Example:
** <Java>
** public class Owner {
**      protected MyProxy myProxy;
**      [...]
** }
** 
** <C>
**  DataStructure *recovered;
**  jobject owner;
**  JNIEnv *env;
**  [...]
**  if(JSS_getPtrFromProxyOwner(env, owner, "myProxy", (void**)&recovered)
**              != PR_SUCCESS) {
**      return;  // exception was thrown!
**  }
*/
PRStatus
JSS_getPtrFromProxyOwner(JNIEnv *env, jobject proxyOwner, char* proxyFieldName,
	char *proxyFieldSig, void **ptr);

/*
 * Turn a C pointer into a Java byte array. The byte array can be passed
 * into a NativeProxy constructor.
 *
 * Returns a byte array containing the pointer, or NULL if an exception
 * was thrown.
 */
jbyteArray
JSS_ptrToByteArray(JNIEnv *env, void *ptr);

/************************************************************************
 *
 * J S S _ w i p e C h a r A r r a y
 *
 * Given a string, set it to all zeroes. Don't pass in NULL.
 */
void
JSS_wipeCharArray(char* array);

/**********************************************************************
 *
 * J S S _ t r a c e
 *
 * Sends a trace message.
 *
 * INPUTS
 *      level
 *          The trace level (see below for constants).  Must be > 0.
 *      mesg
 *          The trace message.  Must not be NULL.
 */
void
JSS_trace(JNIEnv *env, jint level, char *mesg);

/* trace levels */
#define JSS_TRACE_ERROR         1
#define JSS_TRACE_VERBOSE       5
#define JSS_TRACE_OBNOXIOUS     10

/***********************************************************************
 * J S S _ S E C I t e m T o B y t e A r r a y
 *
 * Copies the contents of a SECItem into a new Java byte array.
 *
 * item
 *      A SECItem. Must not be NULL.
 * RETURNS
 *      A Java byte array. NULL will be returned if an exception was
 *      thrown.
 */
jbyteArray
JSS_SECItemToByteArray(JNIEnv *env, SECItem *item);

/***********************************************************************
 * J S S _ B y t e A r r a y T o S E C I t e m
 *
 * Copies the contents of a Java byte array into a new SECItem.
 *
 * byteArray
 *      A Java byte array. Must not be NULL.
 * RETURNS
 *      A newly allocated SECItem, or NULL iff an exception was thrown.
 */
SECItem*
JSS_ByteArrayToSECItem(JNIEnv *env, jbyteArray byteArray);

/***********************************************************************
 * J S S _ s t r e r r o r
 *
 * Provides string representations for NSPR, SEC, and SSL errors.
 * Swiped from PSM.
 *
 * RETURNS
 *      A UTF-8 encoded constant error string for errNum.
 *      NULL if errNum is unknown.
 */
const char *
JSS_strerror(PRErrorCode errNum);


/***********************************************************************
**
** J S S _ t h r o w M s g P r E r r A r g
**
** Throw an exception in native code.  You should return right after
** calling this function.
**
** throwableClassName is the name of the throwable you are throwing in
** JNI class name format (xxx/xx/xxx/xxx). It must not be NULL.
**
** message is the message parameter of the throwable. It must not be NULL.
** If you don't have a message, call JSS_throw.
**
** errCode is a PRErrorCode returned from PR_GetError().
**
** Example:
**      JSS_throwMsg(env, ILLEGAL_ARGUMENT_EXCEPTION, PR_GetError());
**      return -1;
*/
void
JSS_throwMsgPrErrArg(JNIEnv *env, const char *throwableClassName,
    const char *message, PRErrorCode errCode);

#define JSS_throwMsgPrErr(e, cn, m) \
    JSS_throwMsgPrErrArg((e), (cn), (m), PR_GetError())

#define JSS_throwMsgPortErr(e, cn, m) \
    JSS_throwMsgPrErrArg((e), (cn), (m), PORT_GetError())

/************************************************************************
**
** J S S _ i n i t E r r c o d e T r a n s l a t i o n T a b l e.
**
** Initializes the error code translation table. This should be called
** by CryptoManager.initialize(), and must be called before any calls to
** JSS_ConvertNativeErrcodeToJava.
**
*/
void JSS_initErrcodeTranslationTable();

/************************************************************************
**
** J S S _ C o n v e r t N a t i v e E r r c o d e T o J a v a
**
** Converts an NSPR or NSS error code to a Java error code.
** (defined in the class o.m.util.NativeErrcodes)
**
** Returns
**  The Java error code, or -1 if a corresponding Java error code could
**  not be found.
*/
int JSS_ConvertNativeErrcodeToJava(int nativeErrcode);

/************************************************************************
** JSS_ToByteArray.
**
** Converts the given chararacter array to a Java byte array.
**
** Returns
**  The new jbyteArray object or NULL on failure.
*/
jbyteArray JSS_ToByteArray(JNIEnv *env, const void *data, int length);

/************************************************************************
** JSS_RefByteArray.
**
** References the contents of a Java ByteArray into *data, and optionally
** records length information to *lenght. Must be dereferenced via calling
** JSS_DerefByteArray.
**
** Returns
**  bool - whether or not the operation succeeded.
*/
bool JSS_RefByteArray(JNIEnv *env, jbyteArray array, jbyte **data,
    jsize *length);

/************************************************************************
** JSS_DerefByteArray.
**
** Dereferences the specified ByteArray and passed reference. mode is the
** same as given to (*env)->ReleaseByteArrayElements: 0 for copy and free,
** JNI_COMMIT for copy without freeing, and JNI_ABORT for free-only.
**
*/
void JSS_DerefByteArray(JNIEnv *env, jbyteArray array, void *data, jint mode);

/************************************************************************
** JSS_FromByteArray.
**
** Converts the given chararacter array from a Java byte array into a array of
** uint_t. When length is passed and is not NULL, *length is updated with the
** length of the array.
**
** Returns
**  bool - whether or not the operation succeeded.
*/
bool JSS_FromByteArray(JNIEnv *env, jbyteArray array, uint8_t **data,
    size_t *length);

/************************************************************************
** JSS_RefJString
**
** Converts the given jstring object to a char *; must be freed with
** JSS_DerefJString().
**
** Returns
**  A reference to the characters underlying the given string.
*/
const char *JSS_RefJString(JNIEnv *env, jstring str);

/************************************************************************
** JSS_DerefJString
**
** Returns the reference given by the JVM to a jstring's contents.
**
*/
void JSS_DerefJString(JNIEnv *env, jstring str, const char *ref);

/************************************************************************
** JSS_PK11_WrapCertToChain
**
** Inquires about the certificate chain for cert, and returns the full or
** partial as a jobjectArray for use in JNI'd code.
**
*/
jobjectArray JSS_PK11_WrapCertToChain(JNIEnv *env, CERTCertificate *cert,
                                      SECCertUsage certUsage);

/************************************************************************
** JSS_ExceptionToSECStatus
**
** When the JNI has thrown a known exception, convert this to a SECStatus
** code and set the appropriate PRErrorCode.
**
** The supported exceptions are:
**  - CertificateException
**
*/
SECStatus JSS_ExceptionToSECStatus(JNIEnv *env);

/************************************************************************
** JSS_SECStatusToException
**
** Convert a failing SECStatus and PRErrorCode combination into a raised
** JNI exception.
**
** The supported exceptions are:
**  - CertificateException
**
*/
void JSS_SECStatusToException(JNIEnv *env, SECStatus result, PRErrorCode code);

/************************************************************************
** JSS_SECStatusToException
**
** Convert a failing SECStatus and PRErrorCode combination into a raised
** JNI exception with the specified message.
**
** The supported exceptions are:
**  - CertificateException
**
*/
void JSS_SECStatusToExceptionMessage(JNIEnv *env, SECStatus result,
                                     PRErrorCode code, const char *message);

PR_END_EXTERN_C

#endif
