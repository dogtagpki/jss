/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef ORG_MOZILLA_JSS_SSL_JSSL_H
#define ORG_MOZILLA_JSS_SSL_JSSL_H

struct JSSL_SocketData {
    PRFileDesc *fd;
    jobject socketObject; /* weak global ref */
    jobject certApprovalCallback; /* global ref */
    jobject clientCertSelectionCallback; /* global ref */
    CERTCertificate *clientCert;
    PK11SlotInfo *clientCertSlot;
    PRFilePrivate *jsockPriv;
    PRLock *lock;  /* protects reader, writer, accepter, and closePending */
    PRThread *reader;
    PRThread *writer;
    PRThread *accepter;
    PRBool closePending;
};
typedef struct JSSL_SocketData JSSL_SocketData;

SECStatus
JSSL_JavaCertAuthCallback(void *arg, PRFileDesc *fd, PRBool checkSig,
             PRBool isServer);

void
JSSL_HandshakeCallback(PRFileDesc *fd, void *arg);

SECStatus
JSSL_DefaultCertAuthCallback(void *arg, PRFileDesc *fd, PRBool checkSig,
             PRBool isServer);

SECStatus
JSSL_CallCertSelectionCallback(    void * arg,
            PRFileDesc *        fd,
            CERTDistNames *     caNames,
            CERTCertificate **  pRetCert,
            SECKEYPrivateKey ** pRetKey);

SECStatus
JSSL_ConfirmExpiredPeerCert(void *arg, PRFileDesc *fd, PRBool checkSig,
             PRBool isServer);

SECStatus
JSSL_GetClientAuthData( void * arg,
                        PRFileDesc *        fd,
                        CERTDistNames *     caNames,
                        CERTCertificate **  pRetCert,
                        SECKEYPrivateKey ** pRetKey);


#ifdef JDK1_2
/* JDK 1.2 and higher provide weak references in JNI. */

#define NEW_WEAK_GLOBAL_REF(env, obj) \
    ((*env)->NewWeakGlobalRef((env), (obj)))
#define DELETE_WEAK_GLOBAL_REF(env, obj) \
    ((*env)->DeleteWeakGlobalRef((env), (obj)))

#else
/* JDK 1.1 doesn't have weak references, so we'll have to use regular ones */

#define NEW_WEAK_GLOBAL_REF(env, obj) \
    ((*env)->NewGlobalRef((env), (obj)))
#define DELETE_WEAK_GLOBAL_REF(env, obj) \
    ((*env)->DeleteGlobalRef((env), (obj)))

#endif

#define JSSL_getSockData(env, sockObject, sdptr) \
    JSS_getPtrFromProxyOwner(env, sockObject, SSLSOCKET_PROXY_FIELD, \
        SSLSOCKET_PROXY_SIG, (void**)sdptr)


void
JSSL_DestroySocketData(JNIEnv *env, JSSL_SocketData *sd);


extern PRInt32 JSSL_enums[];

JSSL_SocketData*
JSSL_CreateSocketData(JNIEnv *env, jobject sockObj, PRFileDesc* newFD,
        PRFilePrivate *priv);

#define SSL_POLICY_DOMESTIC 0
#define SSL_POLICY_EXPORT 1
#define SSL_POLICY_FRANCE 2

typedef enum {LOCAL_SOCK, PEER_SOCK} LocalOrPeer;

PRStatus
JSSL_getSockAddr
    (JNIEnv *env, jobject self, PRNetAddr *addr, LocalOrPeer localOrPeer);

PRFileDesc*
JSS_SSL_javasockToPRFD(JNIEnv *env, jobject sockObj);

jthrowable
JSS_SSL_getException(PRFilePrivate *priv);

void
JSS_SSL_processExceptions(JNIEnv *env, PRFilePrivate *priv);

#define EXCEPTION_CHECK(env, sock) \
    if( sock != NULL && sock->jsockPriv!=NULL) { \
        JSS_SSL_processExceptions(env, sock->jsockPriv); \
    }


void JSSL_throwSSLSocketException(JNIEnv *env, char *message);

#endif
