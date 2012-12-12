/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* need to include these first:
 *
 * certt.h
 * nspr.h
 * jni.h
 * secmodt.h
 */

#ifndef JSS_PK11_UTIL_H
#define JSS_PK11_UTIL_H

PR_BEGIN_EXTERN_C


/*=====================================================================
                              K E Y S
=====================================================================*/

/***********************************************************************
 *
 * J S S _ P K 1 1 _ w r a p P r i v K e y
 * privk: will be eaten by the wrapper and set to NULL.
 * Returns: a new PK11PrivKey, or NULL if an exception occurred.
 */
jobject
JSS_PK11_wrapPrivKey(JNIEnv *env, SECKEYPrivateKey **privk);

/***********************************************************************
 *
 * J S S _ P K 1 1 _ w r a p P u b K e y
 * privk: will be eaten by the wrapper and set to NULL.
 * Returns: a new PK11PubKey, or NULL if an exception occurred.
 */
jobject
JSS_PK11_wrapPubKey(JNIEnv *env, SECKEYPublicKey **pubk);


/**************************************************************************
 * Given a PrivateKey object, extracts the SECKEYPrivateKey* and stores it
 * at the given address.
 *
 * privkObject: A JNI reference to a PrivateKey object.
 * ptr: Address of a SECKEYPrivateKey* that will receive the pointer.
 * Returns: PR_SUCCESS for success, PR_FAILURE if an exception was thrown.
 */
PRStatus
JSS_PK11_getPrivKeyPtr(JNIEnv *env, jobject privkObject,
    SECKEYPrivateKey** ptr);

/***********************************************************************
 * Given a PublicKey object, extracts the SECKEYPublicKey* and stores it
 * at the given address.
 *
 * pubkObject: A JNI reference to a PublicKey object.
 * ptr: Address of a SECKEYPublicKey* that will receive the pointer.
 * Returns: PR_SUCCESS for success, PR_FAILURE if an exception was thrown.
 */
PRStatus
JSS_PK11_getPubKeyPtr(JNIEnv *env, jobject pubkObject,
    SECKEYPublicKey** ptr);

/***********************************************************************
 * J S S _ P K 1 1 _ g e t S y m K e y P t r
 *
 * Given a Java PK11SymKey, extracts the C PK11SymKey and stores it at
 * the given address.
 */
PRStatus
JSS_PK11_getSymKeyPtr(JNIEnv *env, jobject symKeyObject, PK11SymKey **ptr);

/***********************************************************************
 *
 * J S S _ P K 1 1 _ w r a p S y m K e y
 * symKey: will be stored in a Java wrapper.
 * Returns: a new PK11SymKey, or NULL if an exception occurred.
 */
jobject
JSS_PK11_wrapSymKey(JNIEnv *env, PK11SymKey **symKey);

/***********************************************************************
 * JSS_PK11_getKeyType
 *
 * Converts a PrivateKey.KeyType object to a PKCS #11 key type.
 *
 * INPUTS
 *      keyTypeObj
 *          A org.mozilla.jss.crypto.PrivateKey.KeyType object.
 * RETURNS
 *  The key type, or nullKey if an exception occurred.
 */
KeyType
JSS_PK11_getKeyType(JNIEnv *env, jobject keyTypeObj);

/***********************************************************************
 * JSS_PK11_generateKeyPair
 *
 * Create a new key pair based on the passed in mechanism and parameters
 *
 * INPUTS
 *      mechanism
 *          A PKCS#11 KeyPair Mechanism
 *      slot
 *          Slot to generate the keypair in.
 *      pubk
 *          returned public key
 *      privk
 *          returned private key key
 *      param
 *          PKCS #11 mechanism parameters
 *      temporary
 *          boolean to say if the key is temporary or permanent
 *      sensitive
 *          int to say if the key should be sensitive or not (-1 is default)
 *      extractable
 *          int to say if the key should be extractable or not (-1 is default)
 * RETURNS
 *  The SECStatus, SECSuccess of success, SECFailure on failure
 */
SECStatus
JSS_PK11_generateKeyPair(JNIEnv *env, CK_MECHANISM_TYPE mechanism,
    PK11SlotInfo *slot, SECKEYPublicKey **pubk, SECKEYPrivateKey **privK,
    void *params, PRBool temporary, jint senstive, jint extractable);

SECStatus
JSS_PK11_generateKeyPair_withOpFlags(JNIEnv *env, CK_MECHANISM_TYPE mechanism,
    PK11SlotInfo *slot, SECKEYPublicKey **pubk, SECKEYPrivateKey **privk,
    void *params, PRBool temporary, jint sensitive, jint extractable,
    jint op_flags, jint op_flags_mask);

/*=====================================================================
                       C E R T I F I C A T E S
=====================================================================*/



/******************************************************************
 *
 * J S S _ P K 1 1 _ g e t C e r t P t r
 *
 * Given a PK11Cert object, extracts the CERTCertificate* and
 * stores it at the given address.
 *
 * certObject: A JNI reference to a JSS Certificate object.
 * ptr: Address of a CERTCertificate* that will receive the pointer.
 * Returns: PR_SUCCESS for success, PR_FAILURE if an exception was thrown.
 */
PRStatus
JSS_PK11_getCertPtr(JNIEnv *env, jobject certObject, CERTCertificate **ptr);


/******************************************************************
 *
 * J S S _ P K 1 1 _ g e t C e r t S l o t P t r
 *
 * Given a PK11Cert object, extracts the PK11SlotInfo* and
 * stores it at the given address.
 *
 * certObject: A JNI reference to a JSS Certificate object.
 * ptr: Address of a PK11SlotInfo* that will receive the pointer.
 * Returns: PR_SUCCESS for success, PR_FAILURE if an exception was thrown.
 */
PRStatus
JSS_PK11_getCertSlotPtr(JNIEnv *env, jobject certObject, PK11SlotInfo **ptr);


/*************************************************************************
 *
 * J S S _ P K 1 1 _ f i n d C e r t A n d S l o t F r o m N i c k n a m e
 *
 * A variant of NSS's PK11_FindCertFromNickname function that also
 * returns a PK11SlotInfo* in *ppSlot.
 *
 * If nickname is of the format "token:nickname", the slot that
 * contains the specified token is returned.  Otherwise the internal
 * key slot (which contains the permanent database token) is returned.
 */
CERTCertificate *
JSS_PK11_findCertAndSlotFromNickname(char *nickname, void *wincx,
    PK11SlotInfo **ppSlot);


/***************************************************************************
 *
 * J S S _ P K 1 1 _ f i n d C e r t s A n d S l o t F r o m N i c k n a m e
 *
 * A variant of NSS's PK11_FindCertsFromNickname function that also
 * returns a PK11SlotInfo* in *ppSlot.
 *
 * If nickname is of the format "token:nickname", the slot that
 * contains the specified token is returned.  Otherwise the internal
 * key slot (which contains the permanent database token) is returned.
 */
CERTCertList *
JSS_PK11_findCertsAndSlotFromNickname(char *nickname, void *wincx,
    PK11SlotInfo **ppSlot);


/***********************************************************************
 *
 * J S S _ P K 1 1 _ w r a p C e r t A n d S l o t A n d N i c k n a m e
 *
 * Builds a PK11Cert object from a CERTCertificate, a PK11SlotInfo, and
 *	a nickname.
 * ppCert: Pointer to pointer to CERTCertificate.  The CERTCertificate
 *      will be wrapped in a Java certificate.  If this fails, it
 *      will be deleted.  In any case, the caller should never worry about,
 *      or use, this CERTCertificate again. To enforce this, *ppCert
 *      will be set to NULL whether the functions fails or succeeds.
 * ppSlot: Pointer to pointer to PK11SlotInfo.  The PK11SlotInfo
 *      will be wrapped in a Java certificate.  If this fails, it
 *      will be deleted.  In any case, the caller should never worry about,
 *      or use, this PK11SlotInfo again. To enforce this, *ppSlot
 *      will be set to NULL whether the functions fails or succeeds.
 * nickname: the cert instance's nickname.
 * Returns: a new Java PK11Cert object, or NULL if an exception was thrown.
 */
jobject
JSS_PK11_wrapCertAndSlotAndNickname(JNIEnv *env, CERTCertificate **ppCert,
    PK11SlotInfo **ppSlot, const char *nickname);


/****************************************************************
 *
 * J S S _ P K 1 1 _ w r a p C e r t A n d S l o t
 *
 * Builds a PK11Cert object from a CERTCertificate and a PK11SlotInfo.
 * ppCert: Pointer to pointer to CERTCertificate.  The CERTCertificate
 *      will be wrapped in a Java certificate.  If this fails, it
 *      will be deleted.  In any case, the caller should never worry about,
 *      or use, this CERTCertificate again. To enforce this, *ppCert
 *      will be set to NULL whether the functions fails or succeeds.
 * ppSlot: Pointer to pointer to PK11SlotInfo.  The PK11SlotInfo
 *      will be wrapped in a Java certificate.  If this fails, it
 *      will be deleted.  In any case, the caller should never worry about,
 *      or use, this PK11SlotInfo again. To enforce this, *ppSlot
 *      will be set to NULL whether the functions fails or succeeds.
 * Returns: a new Java PK11Cert object, or NULL if an exception was thrown.
 */
jobject
JSS_PK11_wrapCertAndSlot(JNIEnv *env, CERTCertificate **ppCert,
    PK11SlotInfo **ppSlot);


/****************************************************************
 *
 * J S S _ P K 1 1 _ w r a p C e r t
 *
 * Builds a PK11Cert object from a CERTCertificate.
 * ppCert: Pointer to pointer to CERTCertificate.  The CERTCertificate
 *      will be wrapped in a Java certificate.  If this fails, it
 *      will be deleted.  In any case, the caller should never worry about,
 *      or use, this CERTCertificate again. To enforce this, *ppCert
 *      will be set to NULL whether the functions fails or succeeds.
 * Returns: a new Java PK11Cert object, or NULL if an exception was thrown.
 *
 * Use JSS_PK11_wrapCertAndSlot instead if it is important for the PK11Cert
 * object to have the correct slot pointer or the slot pointer is readily
 * available.
 */
jobject
JSS_PK11_wrapCert(JNIEnv *env, CERTCertificate **ppCert);


/*=====================================================================
                            S T O R E S
=====================================================================*/

/************************************************************************
 *
 * J S S _ g e t S t o r e S l o t P t r
 *
 * Retrieve the PK11SlotInfo pointer of the given PK11Store.
 *
 * INPUTS
 *      store
 *          A reference to a Java PK11Store
 *      slot
 *          address of a PK11SlotInfo* that will be loaded with
 *          the PK11SlotInfo pointer of the given token.
 * RETURNS
 *      PR_SUCCESS if the operation was successful, PR_FAILURE if an
 *      exception was thrown.
 */
PRStatus
JSS_PK11_getStoreSlotPtr(JNIEnv *env, jobject store, PK11SlotInfo **slot);



/*=====================================================================
                            T O K E N S
=====================================================================*/



/******************************************************************
**
** J S S _ P K 1 1 _ m a k e C r y p t o T o k e n F r o m P K 1 1
**
** Returns a new CryptoToken object, or NULL if an exception was thrown.
**/
jobject
JSS_PK11_makeCryptoTokenFromPK11(JNIEnv *env, jobject pk11token);

/***********************************************************************
 *
 * J S S _ P K 1 1 _ w r a p P K 1 1 T o k e n
 *
 * Create a PK11Token object from a PKCS #11 slot.
 *
 * slot is a pointer to a PKCS #11 slot, which must not be NULL. It will
 * be eaten by the wrapper and set to NULL.
 *
 * Returns a new PK11Token object, or NULL if an exception was thrown.
 */
jobject
JSS_PK11_wrapPK11Token(JNIEnv *env, PK11SlotInfo **slot);

/************************************************************************
 *
 * J S S _ P K 1 1 _ g e t T o k e n S l o t P t r
 *
 * Retrieve the PK11SlotInfo pointer of the given token.
 *
 * tokenObject: A reference to a Java PK11Token
 * ptr: address of a PK11SlotInfo* that will be loaded with the PK11SlotInfo
 *      pointer of the given token.
 * returns: PR_SUCCESS if the operation was successful, PR_FAILURE if an
 *      exception was thrown.
 */
PRStatus
JSS_PK11_getTokenSlotPtr(JNIEnv *env, jobject tokenObject, PK11SlotInfo **ptr);



/*=====================================================================
                             M O D U L E S
=====================================================================*/
/***********************************************************************
 *
 * J S S _ P K 1 1 _ w r a p P K 1 1 M o d u l e
 *
 * Turns a SECMODModule* C structure into a PK11Module Java object.
 *
 * INPUTS
 *      ptr
 *          Address of a SECMODModule *. This pointer will be copied
 *          into the new Java object, then set to NULL.
 * RETURNS
 *      A new Java PK11Module object, or NULL if an exception was thrown.
 *      In any case, the ptr parameter is eaten.
 */
jobject
JSS_PK11_wrapPK11Module(JNIEnv *env, SECMODModule **module);


/***********************************************************************
 *
 * J S S _ P K 1 1 _ g e t M o d u l e P t r
 *
 * Retrieve the SECMODModule pointer of the given PK11Module.
 *
 * INPUTS
 *      module
 *          A reference to a Java PK11Module.
 *      ptr
 *          Address of a SECMODModule * that will be loaded with the
 *          SECMODModule pointer of the given PK11Module.
 * RETURNS
 *      PR_FAILURE if an exception was thrown, or PR_SUCCESS if the
 *      peration succeeded.
 */
PRStatus
JSS_PK11_getModulePtr(JNIEnv *env, jobject module, SECMODModule **ptr);




/*=====================================================================
                           C O N T E X T S
=====================================================================*/


typedef enum { SGN_CONTEXT, VFY_CONTEXT } SigContextType;
typedef struct SigContextProxyStr SigContextProxy;

/***********************************************************************
 * J S S _ P K 1 1 _ g e t S i g C o n t e x t
 *
 * Extracts the context pointer from a ContextProxy.
 * proxy: a non-NULL SigContextProxy object.
 * ptr: address of a SGNContext* or VFYContext* where the pointer will
 *      be stored.
 * type: address of a SigContextType where the type of context will
 *      be stored.
 * Returns: PR_SUCCESS, unless an exception was thrown.
 */
PRStatus
JSS_PK11_getSigContext(JNIEnv *env, jobject proxy, void**pContext,
        SigContextType* pType);

/**********************************************************************
 *
 * J S S _ P K 1 1 _ m a k e S i g C o n t e x t P r o x y
 *
 * Wraps a context in a ContextProxy.
 *
 * ctxt: address of a SGNContext* or VFYContext* that must not be NULL.
 * It will be eaten by the wrapper and set to NULL.
 * type: the type of context, SGN_CONTEXT or VFY_CONTEXT.
 * Returns: a new ContextProxy object wrapping the given context,
 *  or NULL if an exception was thrown.
 */
jobject
JSS_PK11_wrapSigContextProxy(JNIEnv *env, void **ctxt, SigContextType type);

/***********************************************************************
 *
 * J S S _ P K 1 1 _ g e t C i p h e r C o n t e x t
 *
 * Extracts the PK11Context from a CipherContextProxy.
 *
 * proxy
 *      A CipherContextProxy.
 *
 * pContext
 *      Address of a PK11Context*, which will be filled with the pointer
 *      extracted from the CipherContextProxy.
 *
 * RETURNS
 *      PR_SUCCESS for success, or PR_FAILURE if an exception was thrown.
 */
PRStatus
JSS_PK11_getCipherContext(JNIEnv *env, jobject proxy, PK11Context **pContext);


/***********************************************************************
 *
 * J S S _ P K 1 1 _ w r a p C i p h e r C o n t e x t P r o x y
 *
 * Wraps a PK11Context in a CipherContextProxy.
 *
 * context
 *      address of a pointer to a PK11Context, which must not be NULL.
 *      It will be eaten by the wrapper and set to NULL, even if the
 *      function returns NULL.
 *
 * RETURNS
 *      A new CipherContextProxy, or NULL if an exception was thrown.
 */
jobject
JSS_PK11_wrapCipherContextProxy(JNIEnv *env, PK11Context **context);


/*=====================================================================
                       P K C S # 1 1  H A C K S
=====================================================================*/

/***********************************************************************
 *
 * J S S _ P K 1 1 _ g e t N e w S e s s i o n
 *
 * Creates a new session.  If one cannot be created, the common shared session
 *      is returned, and *owner is set to PR_FALSE.  Otherwise, the new
 *      session is returned and *owner is set to PR_TRUE.
 *
 * slot
 *      The slot on which to open a session.
 * owner
 *      Pointer to a PRBool which will set to PR_TRUE if a new session was
 *      created, and to PR_FALSE if the shared session was returned.
 *
 * RETURNS
 *      A session that can be used for cryptographic operations.  If *owner
 *      is false, the session is not owned by the called but rather is shared.
 */
CK_SESSION_HANDLE
JSS_PK11_getNewSession(PK11SlotInfo *slot, PRBool *owner);

/***********************************************************************
 *
 * J S S _ P K 1 1 _ c l o s e S e s s i o n
 *
 * Closes a session that was returned by JSS_PK11_GetNewSession.
 *
 * slot
 *      The slot on which this session lives.
 *
 * session
 *      The session to close.
 *
 * owner
 *      As returned by JSS_PK11_GetNewSession. PR_TRUE if the session was
 *      created especially for the caller, PR_FALSE if it is the common
 *      shared session.
 */
void
JSS_PK11_closeSession(PK11SlotInfo *slot, CK_SESSION_HANDLE session,
        PRBool owner);

/***********************************************************************
 *
 * J S S _ P K 1 1 _ g e t E r r o r S t r i n g
 *
 * Returns a simple error string for a given PKCS #11 error.
 */
char*
JSS_PK11_getErrorString(CK_RV crv);


PR_END_EXTERN_C

#endif
