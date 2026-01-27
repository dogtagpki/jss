/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <jni.h>
#include <nspr.h>
#include <plstr.h>
#include <seccomon.h>
#include <secitem.h>
#include "jssutil.h"
#include "jss_bigint.h"
#include "jss_exceptions.h"
#include "java_ids.h"
#include "nss.h"
#include "cert.h"
#include "certt.h"
#include "pk11util.h"

#include "secerr.h"
#include "keyhi.h"

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
    const char *message, PRErrorCode errCode)
{
    const char *errStr = JSS_strerror(errCode);
    char *msg = NULL;
    int msgLen;

    if( errStr == NULL ) {
        errStr = "Unknown error";
    }

    msgLen = strlen(message) + strlen(errStr) + 40;
    msg = PR_Malloc(msgLen);
    if( msg == NULL ) {
        JSS_throw(env, OUT_OF_MEMORY_ERROR);
        goto finish;
    }
    PR_snprintf(msg, msgLen, "%s: (%ld) %s", message, errCode, errStr);

    JSS_throwMsg(env, throwableClassName, msg);

finish:
    if(msg != NULL) {
        PR_Free(msg);
    }
}

/***********************************************************************
**
** J S S _ t h r o w M s g
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
** Example:
**      JSS_throwMsg(env, ILLEGAL_ARGUMENT_EXCEPTION,
**          "Bogus argument, you ninny");
**      return -1;
*/
void
JSS_throwMsg(JNIEnv *env, const char *throwableClassName,
    const char *message)
{

    jclass throwableClass;
    jint VARIABLE_MAY_NOT_BE_USED result;

    /* validate arguments */
    PR_ASSERT(env!=NULL && throwableClassName!=NULL && message!=NULL);

    throwableClass = NULL;
    if(throwableClassName) {
        throwableClass = (*env)->FindClass(env, throwableClassName);

        /* make sure the class was found */
        PR_ASSERT(throwableClass != NULL);
    }
    if(throwableClass == NULL) {
        throwableClass = (*env)->FindClass(env, GENERIC_EXCEPTION);
    }
    PR_ASSERT(throwableClass != NULL);

    result = (*env)->ThrowNew(env, throwableClass, message);
    PR_ASSERT(result == 0);
}

/***********************************************************************
**
** J S S _ t h r o w
**
** Throw an exception in native code.  You should return right after
** calling this function.
**
** throwableClassName is the name of the throwable you are throwing in
** JNI class name format (xxx/xx/xxx/xxx). It must not be NULL.
**
** Example:
**      JSS_throw(env, ILLEGAL_ARGUMENT_EXCEPTION);
**      return -1;
*/
void
JSS_throw(JNIEnv *env, char *throwableClassName)
{
    jclass throwableClass;
    jobject throwable;
    jmethodID constructor;
    jint VARIABLE_MAY_NOT_BE_USED result;
    
    PR_ASSERT( (*env)->ExceptionOccurred(env) == NULL );

    /* Lookup the class */
    throwableClass = NULL;
    if(throwableClassName) {
        throwableClass = (*env)->FindClass(env, throwableClassName);

        /* make sure the class was found */
        PR_ASSERT(throwableClass != NULL);
    }
    if(throwableClass == NULL) {
        throwableClass = (*env)->FindClass(env, GENERIC_EXCEPTION);
    }
    PR_ASSERT(throwableClass != NULL);

    /* Lookup up the plain vanilla constructor */
    constructor = (*env)->GetMethodID(
									env,
									throwableClass,
									PLAIN_CONSTRUCTOR,
									PLAIN_CONSTRUCTOR_SIG);
    if(constructor == NULL) {
        /* Anything other than OutOfMemory is a bug */
        ASSERT_OUTOFMEM(env);
        return;
    }

    /* Create an instance of the throwable */
    throwable = (*env)->NewObject(env, throwableClass, constructor);
    if(throwable == NULL) {
        /* Anything other than OutOfMemory is a bug */
        ASSERT_OUTOFMEM(env);
        return;
    }

    /* Throw the new instance */
    result = (*env)->Throw(env, throwable);
    PR_ASSERT(result == 0);
}

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
JSS_getPtrFromProxy(JNIEnv *env, jobject nativeProxy, void **ptr)
{
#ifdef DEBUG
    jclass nativeProxyClass;
#endif
	jclass proxyClass;
    jfieldID byteArrayField;
    jbyteArray byteArray;
    int size;

    PR_ASSERT(env!=NULL && nativeProxy != NULL && ptr != NULL);
    if( nativeProxy == NULL ) {
        JSS_throw(env, NULL_POINTER_EXCEPTION);
        return PR_FAILURE;
    }

	proxyClass = (*env)->GetObjectClass(env, nativeProxy);
	PR_ASSERT(proxyClass != NULL);

#ifdef DEBUG
    nativeProxyClass = (*env)->FindClass(
								env,
								NATIVE_PROXY_CLASS_NAME);
    if(nativeProxyClass == NULL) {
        ASSERT_OUTOFMEM(env);
        return PR_FAILURE;
    }

    /* make sure what we got was really a NativeProxy object */
    PR_ASSERT( (*env)->IsInstanceOf(env, nativeProxy, nativeProxyClass) );
#endif

    byteArrayField = (*env)->GetFieldID(
								env,
								proxyClass,
								NATIVE_PROXY_POINTER_FIELD,
						        NATIVE_PROXY_POINTER_SIG);
    if(byteArrayField==NULL) {
        ASSERT_OUTOFMEM(env);
        return PR_FAILURE;
    }

    byteArray = (jbyteArray) (*env)->GetObjectField(env, nativeProxy,
                        byteArrayField);
    if (byteArray == NULL) {
        *ptr = NULL;
    } else {
        size = sizeof(*ptr);
        PR_ASSERT((*env)->GetArrayLength(env, byteArray) == size);
        (*env)->GetByteArrayRegion(env, byteArray, 0, size, (void*)ptr);
    }

    if( (*env)->ExceptionOccurred(env) ) {
        PR_ASSERT(PR_FALSE);
        return PR_FAILURE;
    } else {
        return PR_SUCCESS;
    }
}

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
	char *proxyFieldSig, void **ptr)
{
    jclass ownerClass;
    jfieldID proxyField;
    jobject proxyObject;

    PR_ASSERT(env!=NULL && proxyOwner!=NULL && proxyFieldName!=NULL &&
        ptr!=NULL);

    /*
     * Get proxy object
     */
    ownerClass = (*env)->GetObjectClass(env, proxyOwner);
    proxyField = (*env)->GetFieldID(env, ownerClass, proxyFieldName,
							proxyFieldSig);
    if(proxyField == NULL) {
        return PR_FAILURE;
    }

    proxyObject = (*env)->GetObjectField(env, proxyOwner, proxyField);
    if (proxyObject == NULL) {
        return PR_FAILURE;
    }

    /*
     * Get the pointer from the Native Reference object
     */
    return JSS_getPtrFromProxy(env, proxyObject, ptr);
}


/***********************************************************************
**
** J S S _ p t r T o B y t e A r r a y
**
** Turn a C pointer into a Java byte array. The byte array can be passed
** into a NativeProxy constructor.
**
** Returns a byte array containing the pointer, or NULL if an exception
** was thrown.
*/
jbyteArray
JSS_ptrToByteArray(JNIEnv *env, void *ptr)
{
    return JSS_ToByteArray(env, (void *)&ptr, sizeof(ptr));
}



/***********************************************************************
 *
 * J S S _ O c t e t S t r i n g T o B y t e A r r a y
 *
 * Converts a representation of an integer as a big-endian octet string
 * stored in a SECItem (as used by the low-level crypto functions) to a
 * representation of an integer as a big-endian Java byte array. Prepends
 * a zero byte to force it to be positive. Returns NULL if an exception
 * occurred.
 *
 */
jbyteArray
JSS_OctetStringToByteArray(JNIEnv *env, SECItem *item)
{
    jbyteArray array;
    jbyte *bytes;
    int size;    /* size of the resulting byte array */

    PR_ASSERT(env != NULL && item->len>0);

    /* allow space for extra zero byte */
    size = item->len+1;

    array = (*env)->NewByteArray(env, size);
    if(array == NULL) {
        ASSERT_OUTOFMEM(env);
        return NULL;
    }

    bytes = (*env)->GetByteArrayElements(env, array, NULL);
    if(bytes == NULL) {
        ASSERT_OUTOFMEM(env);
        return NULL;
    }

    /* insert a 0 as the MSByte to force the string to be positive */
    bytes[0] = 0;

    /* now insert the rest of the bytes */
    memcpy(bytes+1, item->data, size-1);

    JSS_DerefByteArray(env, array, bytes, 0);

    return array;
}

#define ZERO_SECITEM(item) {(item).data=NULL; (item).len=0;}

/***********************************************************************
 *
 * J S S _ B y t e A r r a y T o O c t e t S t r i n g
 *
 * Converts an integer represented as a big-endian Java byte array to
 * an integer represented as a big-endian octet string in a SECItem.
 *
 * INPUTS
 *      byteArray
 *          A Java byte array containing an integer represented in
 *          big-endian format.  Must not be NULL.
 *      item
 *          Pointer to a SECItem that will be filled with the integer
 *          from the byte array, in big-endian format.
 * RETURNS
 *      PR_SUCCESS if the operation was successful, PR_FAILURE if an exception
 *      was thrown.
 */
PRStatus
JSS_ByteArrayToOctetString(JNIEnv *env, jbyteArray byteArray, SECItem *item)
{
    jbyte *bytes=NULL;
    PRStatus status=PR_FAILURE;
    jsize size;

    PR_ASSERT(env!=NULL && byteArray!=NULL && item!=NULL);

    ZERO_SECITEM(*item);

    size = (*env)->GetArrayLength(env, byteArray);
    PR_ASSERT(size > 0);

    bytes = (*env)->GetByteArrayElements(env, byteArray, NULL);
    if(bytes==NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    item->data = (unsigned char*) PR_Malloc(size);
    if(item->data == NULL) {
        JSS_throw(env, OUT_OF_MEMORY_ERROR);
        goto finish;
    }
    item->len = size;

    memcpy(item->data, bytes, size);

    status = PR_SUCCESS;

finish:
    JSS_DerefByteArray(env, byteArray, bytes, JNI_ABORT);
    if(status != PR_SUCCESS) {
        SECITEM_FreeItem(item, PR_FALSE);
    }
    return status;
}

/************************************************************************
 *
 * J S S _ w i p e C h a r A r r a y
 *
 * Given a string, set it to all zeroes. Be a chum and don't pass in NULL.
 */
void
JSS_wipeCharArray(char* array)
{
	PR_ASSERT(array != NULL);
	if(array == NULL) {
		return;
	}

	for(; *array != '\0'; array++) {
		*array = '\0';
	}
}

#ifdef DEBUG
static int debugLevel = JSS_TRACE_VERBOSE;
#else
static int debugLevel = JSS_TRACE_ERROR;
#endif

/**********************************************************************
 *
 * J S S _ t r a c e
 *
 * Sends a trace message.
 *
 * INPUTS
 *      level
 *          The trace level.
 *      mesg
 *          The trace message.  Must not be NULL.
 */
void
JSS_trace(JNIEnv *env, jint level, char *mesg)
{
    PR_ASSERT(env!=NULL && mesg!=NULL);

    if(level <= debugLevel) {
        printf("%s\n", mesg);
        fflush(stdout);
    }
}

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
JSS_assertOutOfMem(JNIEnv *env)
{
    jclass VARIABLE_MAY_NOT_BE_USED memErrClass;
    jthrowable excep;

    PR_ASSERT(env != NULL);

    /* Make sure an exception has been thrown, and save it */
    excep = (*env)->ExceptionOccurred(env);
    PR_ASSERT(excep != NULL);

    /* Clear the exception so we can call JNI exceptions */
    (*env)->ExceptionClear(env);


    /* See if the thrown exception was an OutOfMemoryError */
    memErrClass = (*env)->FindClass(env, "java/lang/OutOfMemoryError");
    PR_ASSERT(memErrClass != NULL);
    PR_ASSERT( (*env)->IsInstanceOf(env, excep, memErrClass) );

    /* Re-throw the exception */
    (*env)->Throw(env, excep);
}

/***********************************************************************
 * Copies the contents of a SECItem into a new Java byte array.
 *
 * item
 *      A SECItem. Must not be NULL.
 * RETURNS
 *      A Java byte array. NULL will be returned if an exception was
 *      thrown.
 */
jbyteArray
JSS_SECItemToByteArray(JNIEnv *env, SECItem *item)
{
    jbyteArray array=NULL;

    PR_ASSERT(env!=NULL && item!=NULL);
    PR_ASSERT(item->len == 0 || item->data != NULL);

    array = (*env)->NewByteArray(env, item->len);
    if( array == NULL ) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    (*env)->SetByteArrayRegion(env, array, 0, item->len, (jbyte*)item->data);

finish:
    return array;
}
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
JSS_ByteArrayToSECItem(JNIEnv *env, jbyteArray byteArray)
{
    SECItem *item = NULL;

    PR_ASSERT(env!=NULL && byteArray!=NULL);

    /* Create a new SECItem */
    item = PR_NEW(SECItem);
    if( item == NULL ) {
        JSS_throw(env, OUT_OF_MEMORY_ERROR);
        goto finish;
    }

    /* Setup the length, allocate the buffer */
    item->len = (*env)->GetArrayLength(env, byteArray);
    item->data = PR_Malloc(item->len);

    /* copy the bytes from the byte array into the SECItem */
    (*env)->GetByteArrayRegion(env, byteArray, 0, item->len,
                (jbyte*)item->data);
    if( (*env)->ExceptionOccurred(env) ) {
        SECITEM_FreeItem(item, PR_TRUE /*freeit*/);
        item = NULL;
    }

finish:
    return item;
}

/************************************************************************
** JSS_ToByteArray.
**
** Converts the given chararacter array to a Java byte array.
**
** Returns
**  The new jbyteArray object or NULL on failure.
*/
jbyteArray JSS_ToByteArray(JNIEnv *env, const void *data, int length)
{
    jbyteArray byteArray;

    byteArray = (*env)->NewByteArray(env, length);
    if (byteArray == NULL) {
        PR_ASSERT((*env)->ExceptionOccurred(env) != NULL);
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, byteArray, 0, length, (jbyte *)data);
    if ((*env)->ExceptionOccurred(env) != NULL) {
        PR_ASSERT(PR_FALSE);
        return NULL;
    }

    return byteArray;
}

/************************************************************************
** JSS_RefByteArray.
**
** References the contents of a Java ByteArray into *data, and optionally
** records length information to *lenght. Must be dereferenced via calling
** JSS_DerefByteArray.
**
** Returns
**  bool - whether or not the operation succeeded. The operation succeeds
**  if *data is successfully referenced (i.e., is non-null).
*/
bool JSS_RefByteArray(JNIEnv *env, jbyteArray array, jbyte **data,
    jsize *length)
{
    bool ret = false;
    jsize array_length = 0;

    if (env == NULL || data == NULL) {
        goto done;
    }
    *data = NULL;

    if (array == NULL) {
        goto done;
    }

    array_length = (*env)->GetArrayLength(env, array);
    if (array_length <= 0) {
        goto done;
    }

    *data = (*env)->GetByteArrayElements(env, array, NULL);
    if (*data != NULL) {
        ret = true;
    }

done:
    if (length != NULL) {
        *length = array_length;
    }
    return ret;
}

/************************************************************************
** JSS_DerefByteArray.
**
** Dereferences the specified ByteArray and passed reference. mode is the
** same as given to (*env)->ReleaseByteArrayElements: 0 for copy and free,
** JNI_COMMIT for copy without freeing, and JNI_ABORT for free-only.
**
*/
void JSS_DerefByteArray(JNIEnv *env, jbyteArray array, void *data, jint mode) {
    if (env == NULL || array == NULL || data == NULL) {
        return;
    }
    (*env)->ReleaseByteArrayElements(env, array, (jbyte *) data, mode);
}

/************************************************************************
** JSS_FromByteArray.
**
** Converts the given chararacter array from a Java byte array into a array of
** uint_t. When length is passed and is not NULL, *length is updated with the
** length of the byte array. The actual allocated size of *data is one more
** than *length to NULL terminate it. Note: *data must be freed with
** free(*data) after use, not with (*env)->ReleaseByteArrayElements.
**
** Returns
**  bool - whether or not the operation succeeded.
*/
bool JSS_FromByteArray(JNIEnv *env, jbyteArray array, uint8_t **data,
    size_t *length)
{
    jsize array_length = 0;
    jbyte *array_data = NULL;

    if (env == NULL || array == NULL || data == NULL) {
        return false;
    }
    *data = NULL;

    if (!JSS_RefByteArray(env, array, &array_data, &array_length)) {
        return false;
    }

    /* Defensive coding: Java's byte arrays are not null terminated, allocate
     * a structure one larger to guarantee C functions work as expected. */
    *data = calloc(array_length + 1, sizeof(uint8_t));
    memcpy(*data, array_data, array_length);

    // Copy length, if specified
    if (length != NULL) {
        *length = array_length;
    }

    // Give back our reference to array_data after destroying the contents.
    JSS_DerefByteArray(env, array, array_data, JNI_ABORT);

    return true;
}

/************************************************************************
** JSS_RefJString
**
** Converts the given jstring object to a char *; must be freed with
** JSS_DerefJString().
**
** Returns
**  A reference to the characters underlying the given string.
*/
const char *JSS_RefJString(JNIEnv *env, jstring str) {
    const char *result = NULL;
    if (str == NULL) {
        return result;
    }

    /* Saving is_copy is useless in most cases: according to the Java
     * docs, we always have to call ReleaseStringUTFChars:
     * https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html */
    result = (*env)->GetStringUTFChars(env, str, NULL);

    /* We've received a NULL result out of a non-NULL input string. This
     * means that the JNI code had an issue parsing the string as UTF8, so
     * raise an exception. */
    if (result == NULL) {
        JSS_throwMsg(env, GENERAL_SECURITY_EXCEPTION,
            "Unable to parse Java String as UTF-8.");
    }

    return result;
}

/************************************************************************
** JSS_DerefJString
**
** Returns the reference given by the JVM to a jstring's contents.
**
*/
void JSS_DerefJString(JNIEnv *env, jstring str, const char *ref) {
    if (str != NULL && ref != NULL) {
        (*env)->ReleaseStringUTFChars(env, str, ref);
    }
}

/************************************************************************
** JSS_PK11_WrapCertToChain
**
** See jssutil.h for more information.
**
*/
jobjectArray JSS_PK11_WrapCertToChain(JNIEnv *env, CERTCertificate *cert, SECCertUsage certUsage) {
    CERTCertList *chain = CERT_GetCertChainFromCert(cert, PR_Now(), certUsage);

    // The only failure cases here are when we're out of memory; in which
    // case, there's not much more for us to do but return NULL.
    if (chain == NULL) {
        return NULL;
    }

    return JSS_PK11_wrapCertChain(env, &chain);
}

/************************************************************************
** JSS_ExceptionToSECStatus
**
** When the JNI has thrown a known exception, convert this to a SECStatus
** code and set the appropriate PRErrorCode.
**
** See jssutil.h for a list of supported exceptions.
**
*/
SECStatus JSS_ExceptionToSECStatus(JNIEnv *env) {
    jclass clazz;

    jthrowable except = (*env)->ExceptionOccurred(env);
    if (except == NULL) {
        // No exception occurred; exit with success.
        PORT_SetError(0);
        return SECSuccess;
    }

    // Now we have to handle get the various cases. Each case involves looking
    // up a class by name and comparing it via IsInstanceOf(...). We ignore
    // failures which may occur on lookup.

    // CERTIFICATE_ENCODING_EXCEPTION <-> SEC_ERROR_CERT_NOT_VALID
    clazz = (*env)->FindClass(env, CERTIFICATE_ENCODING_EXCEPTION);
    if (clazz != NULL && (*env)->IsInstanceOf(env, except, clazz)) {
        PORT_SetError(SEC_ERROR_CERT_NOT_VALID);
        return SECFailure;
    }

    // CERTIFICATE_EXPIRED_EXCEPTION <-> SEC_ERROR_EXPIRED_CERTIFICATE
    clazz = (*env)->FindClass(env, CERTIFICATE_EXPIRED_EXCEPTION);
    if (clazz != NULL && (*env)->IsInstanceOf(env, except, clazz)) {
        PORT_SetError(SEC_ERROR_EXPIRED_CERTIFICATE);
        return SECFailure;
    }

    // CERTIFICATE_NOT_YET_VALID_EXCEPTION <-> SEC_ERROR_CERT_NOT_VALID
    clazz = (*env)->FindClass(env, CERTIFICATE_NOT_YET_VALID_EXCEPTION);
    if (clazz != NULL && (*env)->IsInstanceOf(env, except, clazz)) {
        PORT_SetError(SEC_ERROR_CERT_NOT_VALID);
        return SECFailure;
    }

    // CERTIFICATE_PARSING_EXCEPTION <-> SEC_ERROR_BAD_DER
    clazz = (*env)->FindClass(env, CERTIFICATE_PARSING_EXCEPTION);
    if (clazz != NULL && (*env)->IsInstanceOf(env, except, clazz)) {
        PORT_SetError(SEC_ERROR_BAD_DER);
        return SECFailure;
    }

    // CERTIFICATE_REVOKED_EXCEPTION <-> SEC_ERROR_REVOKED_CERTIFICATE
    clazz = (*env)->FindClass(env, CERTIFICATE_REVOKED_EXCEPTION);
    if (clazz != NULL && (*env)->IsInstanceOf(env, except, clazz)) {
        PORT_SetError(SEC_ERROR_REVOKED_CERTIFICATE);
        return SECFailure;
    }

    // Handle the default case. Since these error messages are mostly
    // user-facing and don't get used internally, setting PR_UNKNOWN_ERROR
    // here is safe.
    PORT_SetError(PR_UNKNOWN_ERROR);
    return SECFailure;
}

/************************************************************************
** JSS_SECStatusToException
**
** Convert a failing SECStatus and PRErrorCode combination into a raised
** JNI exception.
**
** See jssutil.h for a list of supported exceptions.
**
*/
void JSS_SECStatusToException(JNIEnv *env, SECStatus result, PRErrorCode code) {
    JSS_SECStatusToExceptionMessage(env, result, code, "");
}

void JSS_SECStatusToExceptionMessage(JNIEnv *env, SECStatus result, PRErrorCode code, const char *message) {
    if (result == SECSuccess) {
        // We ignore PRErrorCode here. However, while we could clear an
        // exception if it occurred, we don't; that's the caller's choice to
        // make.
        return;
    }

    if (result == SECFailure) {
        switch (code) {
            case SEC_ERROR_CERT_NOT_VALID:
                JSS_throwMsgPrErrArg(env, CERTIFICATE_NOT_YET_VALID_EXCEPTION, message, code);
                break;
            case SEC_ERROR_EXPIRED_CERTIFICATE:
                JSS_throwMsgPrErrArg(env, CERTIFICATE_EXPIRED_EXCEPTION, message, code);
                break;
            case SEC_ERROR_BAD_DER:
                JSS_throwMsgPrErrArg(env, CERTIFICATE_PARSING_EXCEPTION, message, code);
                break;
            case SEC_ERROR_REVOKED_CERTIFICATE:
                JSS_throwMsgPrErrArg(env, CERTIFICATE_REVOKED_EXCEPTION, message, code);
                break;
            default:
                JSS_throwMsgPrErrArg(env, JAVA_LANG_EXCEPTION, message, code);
                break;
        }
    }
}

/***********************************************************************
**
** JSS_clearPtrFromProxy
**
** See also: jssutil.h
*/
PRStatus
JSS_clearPtrFromProxy(JNIEnv *env, jobject nativeProxy)
{
    jclass proxyClass;
    jmethodID nativeProxyClear;

    PR_ASSERT(env!=NULL && nativeProxy != NULL);
    if( nativeProxy == NULL ) {
        JSS_throw(env, NULL_POINTER_EXCEPTION);
        return PR_FAILURE;
    }

    proxyClass = (*env)->GetObjectClass(env, nativeProxy);
    PR_ASSERT(proxyClass != NULL);

    nativeProxyClear = (*env)->GetMethodID(env,
                                           proxyClass,
                                           "clear",
                                           "()V");
    if (nativeProxyClear == NULL) {
        ASSERT_OUTOFMEM(env);
        return PR_FAILURE;
    }

    (*env)->CallVoidMethod(env, nativeProxy, nativeProxyClear);
    if ((*env)->ExceptionOccurred(env)) {
        PR_ASSERT(PR_FALSE);
        return PR_FAILURE;
    } else {
        return PR_SUCCESS;
    }
}

/* V2 refers to PKCS #5 V2 here. If a PKCS #5 v1 or PKCS #12 pbe is passed
 * for pbeTag, then encTag and hashTag are ignored. If pbe is an encryption
 * algorithm, then PKCS #5 V2 is used with prfTag for the prf. If prfTag isn't
 * supplied prf will be SEC_OID_HMAC_SHA1 
 * JSS ported version of nss routine :   PK11_ExportEncryptedPrivateKeyInfoV2 */
SECKEYEncryptedPrivateKeyInfo *
JSS_ExportEncryptedPrivKeyInfoV2(
    PK11SlotInfo *slot,   /* optional, encrypt key in this slot */
    SECOidTag pbeAlg,     /* PBE algorithm to encrypt the with key */
    SECOidTag encAlg,     /* Encryption algorithm to Encrypt the key with */
    SECOidTag prfAlg,     /* Hash algorithm for PRF */
    SECItem *pwitem,      /* password for PBE encryption */
    SECKEYPrivateKey *pk, /* encrypt this private key */
    int iteration,        /* interations for PBE alg */
    void *pwArg)          /* context for password callback */
{
    SECKEYEncryptedPrivateKeyInfo *epki = NULL;
    PLArenaPool *arena = NULL;
    SECAlgorithmID *algid;
    // Make this alg set to what the routine sec_pkcs5CreateAlgorithmID sets it to.
    // From here we can't get to this lower level routine, using PK11_CreatePBEV2AlgorithmID.
    SECOidTag pbeAlgTag = SEC_OID_PKCS5_PBKDF2;
    SECItem *crypto_param = NULL;
    PK11SymKey *key = NULL;
    PK11SymKey *finalKey = NULL;
    SECStatus rv = SECSuccess;
    CK_RV crv;
    CK_ULONG encBufLen;
    CK_MECHANISM_TYPE pbeMechType;
    CK_MECHANISM_TYPE cryptoMechType;
    CK_MECHANISM cryptoMech;

    if (!pwitem || !pk) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return NULL;
    }

    algid = PK11_CreatePBEV2AlgorithmID(pbeAlg, encAlg, prfAlg,
                                        0,iteration , NULL);

    if (algid == NULL) {
        return NULL;
    }

    arena = PORT_NewArena(2048);
    if (arena)
        epki = PORT_ArenaZNew(arena, SECKEYEncryptedPrivateKeyInfo);
    if (epki == NULL) {
        rv = SECFailure;
        goto loser;
    }
    epki->arena = arena;

    /* if we didn't specify a slot, use the slot the private key was in */
    if (!slot) {
        slot = pk->pkcs11Slot;
    }

    /* if we specified a different slot, and the private key slot can do the
     * pbe key gen, generate the key in the private key slot so we don't have
     * to move it later */
    pbeMechType = PK11_AlgtagToMechanism(pbeAlgTag);

    if (slot != pk->pkcs11Slot) {
        if (PK11_DoesMechanism(pk->pkcs11Slot, pbeMechType)) {
            slot = pk->pkcs11Slot;

        }
    }

    key = PK11_PBEKeyGen(slot, algid, pwitem, PR_FALSE, pwArg);
    if (key == NULL) {
        rv = SECFailure;
        goto loser;
    }

    cryptoMechType = PK11_GetPBECryptoMechanism(algid, &crypto_param, pwitem);

    if (cryptoMechType == CKM_INVALID_MECHANISM) {
        rv = SECFailure;
        goto loser;
    }

    cryptoMech.mechanism = PK11_GetPadMechanism(cryptoMechType);

    cryptoMech.pParameter = crypto_param ? crypto_param->data : NULL;
    cryptoMech.ulParameterLen = crypto_param ? crypto_param->len : 0;

    /* If the key isn't in the private key slot, move it */
    if (PK11_GetSlotFromKey(key) != pk->pkcs11Slot) {
        PK11SymKey *newkey = PK11_MoveSymKey(pk->pkcs11Slot,
                                             CKA_WRAP, 0, PR_FALSE, key);
	/* We expect the PK11_MoveSymKey to fail in fips mode,
	 * thus the need for further intervention with JSS_KeyExchange
	 */

        if (newkey == NULL) {
            /* couldn't import the wrapping key, try exchanging the
             *  key */
            CK_FLAGS opFlags = 0;
            opFlags |= CKF_WRAP;
            opFlags |= CKF_UNWRAP;
            opFlags |= CKF_DECRYPT;
            opFlags |= CKF_ENCRYPT;
            newkey  = JSS_KeyExchange(slot, cryptoMech.mechanism,
                 CKA_WRAP,opFlags ,
                 PR_FALSE, key);

            if (newkey == NULL) {
                rv = SECFailure;
                goto loser;
            }
            finalKey = newkey;
        } else {
            /* free the old key and use the new key */
            PK11_FreeSymKey(key);
            key = NULL;
            finalKey = newkey;
        }
    } else {
        finalKey = key;
	key = NULL;
    }

    /* we are extracting an encrypted privateKey structure.
     * which needs to be freed along with the buffer into which it is
     * returned.  eventually, we should retrieve an encrypted key using
     * pkcs8/pkcs5.
     */

    encBufLen = 0;

    epki->encryptedData.data = NULL;
    epki->encryptedData.len = 0; // Just get the len we need

    // Modify behavior for KWP since NULL is not returned for crypto_param
    // from PK11_GetPBECryptoMechanism. It returns some default 8 byte iv, which is incorrect.
    int isKeyWrapKWP = 0;
    if(cryptoMech.mechanism == CKM_AES_KEY_WRAP_KWP) {
        isKeyWrapKWP = 1;
    }

    //First call to get get the size.
    crv = PK11_WrapPrivKey(pk->pkcs11Slot,  finalKey,
                            pk,  cryptoMech.mechanism,
                            isKeyWrapKWP ? NULL : crypto_param,  &epki->encryptedData, NULL);

    if (crv != CKR_OK) {
        rv = SECFailure;
        goto loser;
     }

    // If KWP increase buffer size by 8
    // The size value from the first PK11_WrapPrivKey does not account for AES_BLOCK_SIZE

    if(isKeyWrapKWP) {
      epki->encryptedData.len  += 8;
    }

    encBufLen = epki->encryptedData.len;
    epki->encryptedData.data = PORT_ArenaAlloc(arena, encBufLen);

    if (!epki->encryptedData.data) {
        rv = SECFailure;
        goto loser;
    }

    if (!epki->encryptedData.len) {
        rv = SECFailure;
        goto loser;
    }

    crv = PK11_WrapPrivKey(pk->pkcs11Slot,  finalKey,
                            pk,  cryptoMech.mechanism,
                            isKeyWrapKWP ? NULL : crypto_param,  &epki->encryptedData, NULL);

    if (crv != CKR_OK) {
        rv = SECFailure;
        goto loser;
    }

    rv = SECOID_CopyAlgorithmID(arena, &epki->algorithm, algid);

    loser:
    if (crypto_param != NULL) {
        SECITEM_ZfreeItem(crypto_param, PR_TRUE);
        crypto_param = NULL;
    }

    if (key != NULL) {
        PK11_FreeSymKey(key);
    }

    if (finalKey != NULL) {
        PK11_FreeSymKey(finalKey);
    }

    SECOID_DestroyAlgorithmID(algid, PR_TRUE);

    if (rv == SECFailure) {
        if (arena != NULL) {
            PORT_FreeArena(arena, PR_TRUE);
        }
        epki = NULL;
    }

    return epki;
}

/* Routine to exchange a key from one token to another, needed in extreme situations
 * where either we are in  fips mode or a relectant hardware module won't allow the normal calls to work.
 * Based on original work from cipherboy aka ascheel. His code was based on the nss routine: pk11_KeyExchange
 * Note: the isPerm param is not yet observed since nss has no perm variant of PK11_PubUnwrapSymKeyWithMechanism.
 * In the future when this is true, we can change this to observe the perm flag which now is just treated as false.
 */

 
PK11SymKey *
JSS_KeyExchange(PK11SlotInfo *slot, CK_MECHANISM_TYPE type,
                 CK_ATTRIBUTE_TYPE operation, CK_FLAGS flags,
                 PRBool isPerm, PK11SymKey *symKey)
{
    int tempPrivKeyLength = 2048;
    PK11SymKey *newSymKey = NULL;
    SECStatus rv;
    PK11AttrFlags attrFlags = 0;
    /* performance improvement can go here --- use a generated key at startup
     * to generate a per token wrapping key. If it exists, use it, otherwise
     * do a full key exchange. */

    /* find a common Key Exchange algorithm */
    /* RSA */
    int does_pkcs = PK11_DoesMechanism(PK11_GetSlotFromKey(symKey), CKM_RSA_PKCS) && \
                    PK11_DoesMechanism(slot, CKM_RSA_PKCS);
    int does_oaep = PK11_DoesMechanism(slot, CKM_RSA_PKCS_OAEP) && \
                    PK11_DoesMechanism(slot, CKM_RSA_PKCS_OAEP);

    if (does_pkcs || does_oaep) {
        SECKEYPublicKey *pubKey = NULL;
        SECKEYPrivateKey *privKey = NULL;
        SECItem wrapData;
        unsigned int symKeyLength = PK11_GetKeyLength(symKey);

        /* RSA-PKCS requires no parameters, but RSA-OAEP does. Construct with
         * sane defaults in case we end up needing to use them. */
        CK_MECHANISM_TYPE our_mech = CKM_RSA_PKCS_OAEP;
        CK_RSA_PKCS_OAEP_PARAMS oaep_params = {CKM_SHA384, CKG_MGF1_SHA384,
                                               CKZ_DATA_SPECIFIED, NULL, 0};
        SECItem oaep_param = {siBuffer, (unsigned char*)&oaep_params,
                              sizeof(oaep_params)};
        SECItem *mech_param = &oaep_param;

        if (!does_oaep) {
            /* Default to RSA OAEP. If the token does not do RSA OAEP, fall
             * back to RSA PKCS#1v1.5. */
            our_mech = CKM_RSA_PKCS;
            mech_param = NULL;
        }

        wrapData.data = NULL;

        /* Just go ahead and generate a temp private key,
         * since this method is not going to be called often,
	 * and we don't have to worry about finding a key with the
	 * proper attributes..
         */
         PK11RSAGenParams rsaParams;

         rsaParams.keySizeInBits = tempPrivKeyLength;

         rsaParams.pe = 0x10001;
         attrFlags |= PK11_ATTR_SESSION;
         attrFlags |= (PK11_ATTR_SENSITIVE | PK11_ATTR_PRIVATE);

         privKey = PK11_GenerateKeyPairWithOpFlags(slot, CKM_RSA_PKCS_KEY_PAIR_GEN,
                                           &rsaParams, &pubKey,attrFlags, flags,flags, NULL);

        if (privKey == NULL)
            goto rsa_failed;
        if (pubKey == NULL)
            goto rsa_failed;

        wrapData.len = SECKEY_PublicKeyStrength(pubKey);
        if (!wrapData.len)
            goto rsa_failed;
        wrapData.data = PORT_Alloc(wrapData.len);
        if (wrapData.data == NULL)
            goto rsa_failed;
        /* now wrap the keys in and out */
        rv = PK11_PubWrapSymKeyWithMechanism(pubKey, our_mech, mech_param, symKey, &wrapData);
        if (rv == SECSuccess) {
            newSymKey = PK11_PubUnwrapSymKeyWithMechanism(privKey, our_mech, mech_param,
                                                              &wrapData, type, operation,
                                                              symKeyLength);
            /* make sure we wound up where we wanted to be! */
            if (newSymKey && PK11_GetSlotFromKey(newSymKey) != slot) {
                PK11_FreeSymKey(newSymKey);
                newSymKey = NULL;
            }
        }
    rsa_failed:
        if (wrapData.data != NULL)
            PORT_Free(wrapData.data);
        if (privKey != NULL)
            SECKEY_DestroyPrivateKey(privKey);
        if (pubKey != NULL)
            SECKEY_DestroyPublicKey(pubKey);

        return newSymKey;
    }
    PORT_SetError(SEC_ERROR_NO_MODULE);
    return NULL;
}


/*
 * External references to the rcs and sccsc ident information in 
 * jssver.c. These are here to prevent the compiler from optimizing
 * away the symbols in jssver.c
 */
extern const char __jss_base_rcsid[];
extern const char __jss_base_sccsid[];
