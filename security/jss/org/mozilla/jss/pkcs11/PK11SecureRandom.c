/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * NSS and NSPR header files
 */

#include <pk11func.h>
#include <nspr.h>

/*
 * JNI header files
 */

#include "_jni/org_mozilla_jss_pkcs11_PK11SecureRandom.h"

/*
 * JSS header files
 */

#include <jssutil.h>

/*
 * JNI FUNCTION:  PK11SecureRandom.setSeed
 *
 * JNI FUNCTION TYPE:  protected
 *
 * JNI INPUTS:
 *
 *    env
 *        The JNI object through which all JNI functions are referenced
 *
 *    this
 *        A JNI reference to the class which defines this native method
 *
 * INPUTS:
 *
 *    N/A
 *
 * OUTPUTS:
 *
 *    jseed
 *        A JNI array for storage of the random byte seed sequence
 *
 * ERRORS:
 *
 *    N/A
 *
 * RETURN:
 *
 *    Upon success, this method returns a byte array
 *    containing a random byte sequence
 *
 * NOTES:
 *
 *    This routine is called to seed the pseudo-random number generator.
 *
 * JNI NOTES:
 *
 *    Class:     org_mozilla_jss_pkcs11_PK11SecureRandom
 *    Method:    setSeed
 *    Signature: ([B)V
 */

JNIEXPORT void JNICALL
Java_org_mozilla_jss_pkcs11_PK11SecureRandom_setSeed
    ( JNIEnv* env, jobject this, jbyteArray jseed )
{
    /*
     * "JNI" data members
     */

    jbyte*    jdata   = NULL;
    jboolean  jIsCopy = JNI_FALSE;
    jsize     jlen    = 0;


    /*
     * "C" data members
     */

    PRThread*     pThread = NULL;
    SECStatus     status  = PR_FALSE;
    PK11SlotInfo* slot    = NULL;


    /*
     * Perform initial assertions
     */

    PR_ASSERT( env != NULL && this != NULL );


    /*
     * Attach to the external java thread
     */

    pThread = PR_AttachThread( PR_SYSTEM_THREAD, 0, NULL );
    PR_ASSERT( pThread != NULL );


    /*
     * Obtain the appropriate "slot"
     */

    slot = PK11_GetBestSlot( CKM_FAKE_RANDOM, NULL );
    if( slot == NULL ) {
        PR_ASSERT( PR_FALSE );
        goto loser;
    }


    /*
     * Convert "JNI jbyteArray" into "JNI jbyte*" so
     * that it can be cast into a "C unsigned char*"
     */

    jdata = ( *env )->GetByteArrayElements( env, jseed, &jIsCopy );


    /*
     * Retrieve the length of the "JNI jbyteArray"
     * so that it can be cast into a "C int"
     */

    jlen = ( *env )->GetArrayLength( env, jseed );


    /*
     * Seed the pseudo-random number generator;
     * currently, failures from this routine are ignored
     */

    status = PK11_SeedRandom( slot, ( unsigned char* ) jdata, ( int ) jlen );
    if( status != SECSuccess ) {
        PR_ASSERT( PR_FALSE );
        goto loser;
    }


loser:

    /*
     * Copy back the contents of the "JNI jbyte*" and
     * free any resources associated with it
     */

    if(  jIsCopy == JNI_TRUE ) {
        ( *env )->ReleaseByteArrayElements( env, jseed, jdata, 0 );
    }


    /*
     * Free any "C" resources
     */

    if( slot != NULL ) {
        PK11_FreeSlot( slot );
    }
    slot = NULL;


    /*
     * Detach from the external java thread and return
     */

    PR_DetachThread();

    return;
}


/*
 * JNI FUNCTION:  PK11SecureRandom.nextBytes
 *
 * JNI FUNCTION TYPE:  protected
 *
 * JNI INPUTS:
 *
 *    env
 *        The JNI object through which all JNI functions are referenced
 *
 *    this
 *        A JNI reference to the class which defines this native method
 *
 * INPUTS:
 *
 *    N/A
 *
 * OUTPUTS:
 *
 *    jbytes
 *        A JNI array for storage of the random byte sequence
 *
 * ERRORS:
 *
 *    N/A
 *
 * RETURN:
 *
 *    Upon success, this method returns a byte array
 *    containing a random byte sequence
 *
 * NOTES:
 *
 *    This routine is called to generate a pseudo-random number.
 *
 * JNI NOTES:
 *
 *    Class:     org_mozilla_jss_pkcs11_PK11SecureRandom
 *    Method:    nextBytes
 *    Signature: ([B)V
 */

JNIEXPORT void JNICALL
Java_org_mozilla_jss_pkcs11_PK11SecureRandom_nextBytes
    ( JNIEnv* env, jobject this, jbyteArray jbytes )
{
    /*
     * "JNI" data members
     */

    jbyte*    jdata   = NULL;
    jboolean  jIsCopy = JNI_FALSE;
    jsize     jlen    = 0;


    /*
     * "C" data members
     */

    PRThread*     pThread = NULL;
    SECStatus     status  = PR_FALSE;


    /*
     * Perform initial assertions
     */

    PR_ASSERT( env != NULL && this != NULL );


    /*
     * Attach to the external java thread
     */

    pThread = PR_AttachThread( PR_SYSTEM_THREAD, 0, NULL );
    PR_ASSERT( pThread != NULL );


    /*
     * Convert "JNI jbyteArray" into "JNI jbyte*" so
     * that it can be cast into a "C unsigned char*"
     */

    jdata = ( *env )->GetByteArrayElements( env, jbytes, &jIsCopy );


    /*
     * Retrieve the length of the "JNI jbyteArray"
     * so that it can be cast into a "C int"
     */

    jlen = ( *env )->GetArrayLength( env, jbytes );


    /*
     * Generate a pseudo-random number; currently,
     * failures from this routine are ignored
     */

    status = PK11_GenerateRandom( ( unsigned char* ) jdata, ( int ) jlen );
    if( status != SECSuccess ) {
        goto loser;
    }


loser:

    /*
     * Copy back the contents of the "JNI jbyte*" and
     * free any resources associated with it
     */

    if( jIsCopy == JNI_TRUE ) {
        ( *env )->ReleaseByteArrayElements( env, jbytes, jdata, 0 );
    }


    /*
     * Detach from the external java thread and return
     */

    PR_DetachThread();

    return;
}

