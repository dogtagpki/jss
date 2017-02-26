/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <nspr.h>
#include <jni.h>
#include <pk11func.h>
#include <ssl.h>
#include <sslerr.h>

#include <jssutil.h>
#include <jss_exceptions.h>
#include <java_ids.h>
#include <pk11util.h>
#include "_jni/org_mozilla_jss_ssl_SSLSocket.h"
#include "jssl.h"

#ifdef WIN32
#include <winsock.h>
#endif

#define SSL_AF_INET  50
#define SSL_AF_INET6 51

void
JSSL_throwSSLSocketException(JNIEnv *env, char *message)
{
    const char *errStr;
    PRErrorCode nativeErrcode;
    char *msg = NULL;
    int msgLen;
    jclass excepClass;
    jmethodID excepCons;
    jobject excepObj;
    jstring msgString;
    jint VARIABLE_MAY_NOT_BE_USED result;

    /*
     * get the error code and error string
     */
    nativeErrcode = PR_GetError();
    errStr = JSS_strerror(nativeErrcode);
    if( errStr == NULL ) {
        errStr = "Unknown error";
    }

    /*
     * construct the message
     */
    msgLen = strlen(message) + strlen(errStr) + 40;
    msg = PR_Malloc(msgLen);
    if( msg == NULL ) {
        JSS_throw(env, OUT_OF_MEMORY_ERROR);
        goto finish;
    }
    PR_snprintf(msg, msgLen, "%s: (%ld) %s", message, nativeErrcode, errStr);

    /*
     * turn the message into a Java string
     */
    msgString = (*env)->NewStringUTF(env, msg);
    if( msgString == NULL ) goto finish;

        /*
         * Create the exception object. Use java.net.SocketTimeoutException
         * for timeouts, org.mozilla.jss.ssl.SSLSocketException for everything
         * else.
         */
    switch (nativeErrcode) {
        case PR_PENDING_INTERRUPT_ERROR :
            excepClass = (*env)->FindClass(env, INTERRUPTED_IO_EXCEPTION);
            break;
        case PR_IO_ERROR :
            excepClass = (*env)->FindClass(env, IO_EXCEPTION);
            break;
        case PR_IO_TIMEOUT_ERROR :
        case PR_CONNECT_TIMEOUT_ERROR :
            excepClass = (*env)->FindClass(env, SOCKET_TIMEOUT_EXCEPTION);
            break;
        default : /* for all other PR_ERRORs throw SocketException  */
            excepClass = (*env)->FindClass(env, SSLSOCKET_EXCEPTION);
            break;
    }

    PR_ASSERT(excepClass != NULL);
    if( excepClass == NULL ) goto finish;
    
    excepCons = (*env)->GetMethodID(env, excepClass, "<init>",
        "(Ljava/lang/String;)V");
    PR_ASSERT( excepCons != NULL );
    if( excepCons == NULL ) goto finish;
    
    excepObj = (*env)->NewObject(env, excepClass, excepCons, msgString);
    PR_ASSERT(excepObj != NULL);
    if( excepObj == NULL ) goto finish;

    /*
     * throw the exception
     */
    result = (*env)->Throw(env, excepObj);
    PR_ASSERT(result == 0);

finish:
    if( msg != NULL ) {
        PR_Free(msg);
    }
}

/*
 * This is done for regular sockets that we connect() and server sockets,
 * but not for sockets that come from accept.
 */
JNIEXPORT jbyteArray JNICALL
Java_org_mozilla_jss_ssl_SocketBase_socketCreate(JNIEnv *env, jobject self,
    jobject sockObj, jobject certApprovalCallback,
    jobject clientCertSelectionCallback, jobject javaSock, jstring host,jint family)
{
    jbyteArray sdArray = NULL;
    JSSL_SocketData *sockdata = NULL;
    SECStatus status;
    PRFileDesc *newFD = NULL;
    PRFileDesc *tmpFD = NULL;
    PRFilePrivate *priv = NULL;
    int socketFamily = 0;

    if (family != SSL_AF_INET6 && family  != SSL_AF_INET) {
       JSSL_throwSSLSocketException(env,
                "socketCreate() Invalid family!");
            goto finish;
    }
    if( family == SSL_AF_INET)
       socketFamily = PR_AF_INET;
    else
       socketFamily = PR_AF_INET6;

    if( javaSock == NULL ) {
        /* create a TCP socket */
        newFD = PR_OpenTCPSocket(socketFamily);
        if( newFD == NULL ) {
            JSSL_throwSSLSocketException(env,
                "PR_NewTCPSocket() returned NULL");
            goto finish;
        }
    } else {
        newFD = JSS_SSL_javasockToPRFD(env, javaSock);
        if( newFD == NULL ) {
            JSS_throwMsg(env, SOCKET_EXCEPTION,
                "failed to construct NSPR wrapper around java socket");   
            goto finish;
        }
        priv = newFD->secret;
    }

    /* enable SSL on the socket */
    tmpFD = SSL_ImportFD(NULL, newFD);
    if( tmpFD == NULL ) {
        JSSL_throwSSLSocketException(env, "SSL_ImportFD() returned NULL");
        goto finish;
    }
    newFD = tmpFD;

    sockdata = JSSL_CreateSocketData(env, sockObj, newFD, priv);
    if( sockdata == NULL ) {
        goto finish;
    }
    newFD = NULL;

    if( host != NULL ) {
        const char *chars;
        int retval;
        PR_ASSERT( javaSock != NULL );
        chars = (*env)->GetStringUTFChars(env, host, NULL);
        retval = SSL_SetURL(sockdata->fd, chars);
        (*env)->ReleaseStringUTFChars(env, host, chars);
        if( retval ) {
            JSSL_throwSSLSocketException(env,
                "Failed to set SSL domain name");
            goto finish;
        }
    }

    status = SSL_OptionSet(sockdata->fd, SSL_SECURITY, PR_TRUE);
    if( status != SECSuccess ) {
        JSSL_throwSSLSocketException(env,
            "Unable to enable SSL security on socket");
        goto finish;
    }

    /* setup the handshake callback */
    status = SSL_HandshakeCallback(sockdata->fd, JSSL_HandshakeCallback,
                                    sockdata);
    if( status != SECSuccess ) {
        JSSL_throwSSLSocketException(env,
            "Unable to install handshake callback");
        goto finish;
    }

    /* setup the cert authentication callback */
    if( certApprovalCallback != NULL ) {
        /* create global reference to the callback object */
        sockdata->certApprovalCallback =
            (*env)->NewGlobalRef(env, certApprovalCallback);
        if( sockdata->certApprovalCallback == NULL ) goto finish;

        /* install the Java callback */
        status = SSL_AuthCertificateHook(
            sockdata->fd, JSSL_JavaCertAuthCallback,
            (void*) sockdata->certApprovalCallback);
    } else {
        /* install the default callback */
        status = SSL_AuthCertificateHook(
                    sockdata->fd, JSSL_DefaultCertAuthCallback, NULL);
    }
    if( status != SECSuccess ) {
        JSSL_throwSSLSocketException(env,
            "Unable to install certificate authentication callback");
        goto finish;
    }

    /* setup the client cert selection callback */
    if( clientCertSelectionCallback != NULL ) {
        /* create a new global ref */
        sockdata->clientCertSelectionCallback =
            (*env)->NewGlobalRef(env, clientCertSelectionCallback);
        if(sockdata->clientCertSelectionCallback == NULL)  goto finish;

        /* install the Java callback */
        status = SSL_GetClientAuthDataHook(
            sockdata->fd, JSSL_CallCertSelectionCallback,
            (void*) sockdata->clientCertSelectionCallback);
        if( status != SECSuccess ) {
            JSSL_throwSSLSocketException(env,
                "Unable to install client certificate selection callback");
            goto finish;
        }
    }

    /* pass the pointer back to Java */
    sdArray = JSS_ptrToByteArray(env, (void*) sockdata);   
    if( sdArray == NULL ) {
        /* exception was thrown */
        goto finish;
    }

finish:
    if( (*env)->ExceptionOccurred(env) != NULL ) {
        if( sockdata != NULL ) {
            JSSL_DestroySocketData(env, sockdata);
        }
        if( newFD != NULL ) {
            PR_Close(newFD);
        }
    } else {
        PR_ASSERT( sdArray != NULL );
    }
    return sdArray;
}

JSSL_SocketData*
JSSL_CreateSocketData(JNIEnv *env, jobject sockObj, PRFileDesc* newFD,
        PRFilePrivate *priv)
{
    JSSL_SocketData *sockdata = NULL;

    /* make a JSSL_SocketData structure */
    sockdata = PR_Malloc( sizeof(JSSL_SocketData) );
    if( sockdata == NULL ) {
        JSS_throw(env, OUT_OF_MEMORY_ERROR);
        goto finish;
    }
    sockdata->fd = newFD;
    sockdata->socketObject = NULL;
    sockdata->certApprovalCallback = NULL;
    sockdata->clientCertSelectionCallback = NULL;
    sockdata->clientCert = NULL;
    sockdata->clientCertSlot = NULL;
    sockdata->jsockPriv = priv;
    sockdata->lock = NULL;
    sockdata->reader = NULL;
    sockdata->writer = NULL;
    sockdata->accepter = NULL;
    sockdata->closePending = PR_FALSE;

    sockdata->lock = PR_NewLock();
    if( sockdata->lock == NULL ) {
        JSS_throw(env, OUT_OF_MEMORY_ERROR);
        goto finish;
    }

    /*
     * Make a global ref to the socket. Since it is a weak reference, it will
     * get garbage collected if this is the only reference that remains.
     * We do this so that sockets will get closed when they go out of scope
     * in the Java layer.
     */
    sockdata->socketObject = NEW_WEAK_GLOBAL_REF(env, sockObj);
    if( sockdata->socketObject == NULL ) goto finish;

finish:
    if( (*env)->ExceptionOccurred(env) != NULL ) {
        if( sockdata != NULL ) {
            JSSL_DestroySocketData(env, sockdata);
            sockdata = NULL;
        }
    }
    return sockdata;
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_ssl_SocketProxy_releaseNativeResources
    (JNIEnv *env, jobject this)
{
    /* SSLSocket.close and SSLServerSocket.close call	  */
    /* SocketBase.close to destroy all native Resources */
    /* attached to the socket. There is no native resource */
    /* to release after close has been called. This method  */
    /* remains because SocketProxy extends org.mozilla.jss.util.NativeProxy*/
    /* which defines releaseNativeResources as abstract and */
    /* therefore must be implemented by SocketProxy */
}

void
JSSL_DestroySocketData(JNIEnv *env, JSSL_SocketData *sd)
{
    PR_ASSERT(sd != NULL);

    PR_Close(sd->fd);

    if( sd->socketObject != NULL ) {
        DELETE_WEAK_GLOBAL_REF(env, sd->socketObject );
    }
    if( sd->certApprovalCallback != NULL ) {
        (*env)->DeleteGlobalRef(env, sd->certApprovalCallback);
    }
    if( sd->clientCertSelectionCallback != NULL ) {
        (*env)->DeleteGlobalRef(env, sd->clientCertSelectionCallback);
    }
    if( sd->clientCert != NULL ) {
        CERT_DestroyCertificate(sd->clientCert);
    }
    if( sd->clientCertSlot != NULL ) {
        PK11_FreeSlot(sd->clientCertSlot);
    }
    if( sd->lock != NULL ) {
        PR_DestroyLock(sd->lock);
    }
    PR_Free(sd);
}

/*
 * These must match up with the constants defined in SocketBase.java.
 * Note to developer these constants are not all related! i.e. you cannot
 * pass in PR_SHUTDOWN_RCV to setSSLOption etc! Check their usage 
 * in NSS and NSPR before using.
 */
PRInt32 JSSL_enums[] = {
    SSL_ENABLE_SSL2,            /* 0 */         /* ssl.h */
    SSL_ENABLE_SSL3,            /* 1 */         /* ssl.h */
    SSL_ENABLE_TLS,             /* 2 */         /* ssl.h */
    PR_SockOpt_NoDelay,         /* 3 */         /* prio.h */
    PR_SockOpt_Keepalive,       /* 4 */         /* prio.h */
    PR_SHUTDOWN_RCV,            /* 5 */         /* prio.h */
    PR_SHUTDOWN_SEND,           /* 6 */         /* prio.h */
    SSL_REQUIRE_CERTIFICATE,    /* 7 */         /* ssl.h */
    SSL_REQUEST_CERTIFICATE,    /* 8 */         /* ssl.h */
    SSL_NO_CACHE,               /* 9 */         /* ssl.h */
    SSL_POLICY_DOMESTIC,        /* 10 */        /* ssl.h */
    SSL_POLICY_EXPORT,          /* 11 */        /* ssl.h */
    SSL_POLICY_FRANCE,          /* 12 */        /* ssl.h */
    SSL_ROLLBACK_DETECTION,     /* 13 */        /* ssl.h */
    SSL_NO_STEP_DOWN,           /* 14 */        /* ssl.h */
    SSL_ENABLE_FDX,             /* 15 */        /* ssl.h */
    SSL_V2_COMPATIBLE_HELLO,    /* 16 */        /* ssl.h */
    SSL_REQUIRE_NEVER,          /* 17 */        /* ssl.h */
    SSL_REQUIRE_ALWAYS,         /* 18 */        /* ssl.h */
    SSL_REQUIRE_FIRST_HANDSHAKE,/* 19 */        /* ssl.h */
    SSL_REQUIRE_NO_ERROR,       /* 20 */        /* ssl.h */
    SSL_ENABLE_SESSION_TICKETS, /* 21 */        /* ssl.h */
    SSL_ENABLE_RENEGOTIATION,     /* 22 */      /* ssl.h */
    SSL_RENEGOTIATE_NEVER,        /* 23 */      /* ssl.h */
    SSL_RENEGOTIATE_UNRESTRICTED, /* 24 */      /* ssl.h */
    SSL_RENEGOTIATE_REQUIRES_XTN, /* 25 */      /* ssl.h */
    SSL_RENEGOTIATE_TRANSITIONAL, /* 26 */      /* ssl.h */
    SSL_REQUIRE_SAFE_NEGOTIATION, /* 27 */      /* ssl.h */
    0
};

JNIEXPORT void JNICALL
Java_org_mozilla_jss_ssl_SocketBase_socketBind
    (JNIEnv *env, jobject self, jbyteArray addrBA, jint port)
{
    JSSL_SocketData *sock;
    PRNetAddr addr;
    jbyte *addrBAelems = NULL;
    int addrBALen = 0;
    PRStatus status;

    jmethodID supportsIPV6ID;
    jclass socketBaseClass;
    jboolean supportsIPV6 = 0;

    if( JSSL_getSockData(env, self, &sock) != PR_SUCCESS) {
        /* exception was thrown */
        goto finish;
    }

    /*
     * setup the PRNetAddr structure
     */

    /*
     * Do we support IPV6?
     */

    socketBaseClass = (*env)->FindClass(env, SOCKET_BASE_NAME);
    if( socketBaseClass == NULL ) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }
    supportsIPV6ID = (*env)->GetStaticMethodID(env, socketBaseClass,
        SUPPORTS_IPV6_NAME, SUPPORTS_IPV6_SIG);

    if( supportsIPV6ID == NULL ) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }

    supportsIPV6 = (*env)->CallStaticBooleanMethod(env, socketBaseClass,
         supportsIPV6ID);

    memset( &addr, 0, sizeof( PRNetAddr ));

    if( addrBA != NULL ) {
        addrBAelems = (*env)->GetByteArrayElements(env, addrBA, NULL);
        addrBALen = (*env)->GetArrayLength(env, addrBA);

        if( addrBAelems == NULL ) {
            ASSERT_OUTOFMEM(env);
            goto finish;
        }

        if(addrBALen != 4 && addrBALen != 16) {
            JSS_throwMsgPrErr(env, BIND_EXCEPTION,
            "Invalid address in bind!");
             goto finish;
        }

        if( addrBALen == 4) {
            addr.inet.family = PR_AF_INET;
            addr.inet.port = PR_htons(port);
            memcpy(&addr.inet.ip, addrBAelems, 4);

            if(supportsIPV6) {
                addr.inet.family = PR_AF_INET6;
                addr.ipv6.port = PR_htons(port);
                PR_ConvertIPv4AddrToIPv6(addr.inet.ip,&addr.ipv6.ip);
            }

        }  else {   /* Must be 16 and ipv6 */
            if(supportsIPV6) {
                addr.ipv6.family = PR_AF_INET6;
                addr.ipv6.port = PR_htons(port);
                memcpy(&addr.ipv6.ip,addrBAelems, 16);
            }  else {
                JSS_throwMsgPrErr(env, BIND_EXCEPTION,
                    "Invalid address in bind!");
                goto finish;
            }
        }
    } else {
        if(supportsIPV6) {
            status = PR_SetNetAddr(PR_IpAddrAny, PR_AF_INET6, port, &addr);
        } else {
            status = PR_SetNetAddr(PR_IpAddrAny, PR_AF_INET, port, &addr);
        }
    }

    /* do the bind() call */
    status = PR_Bind(sock->fd, &addr);
    if( status != PR_SUCCESS ) {
        JSS_throwMsgPrErr(env, BIND_EXCEPTION,
            "Could not bind to address");
        goto finish;
    }       

finish:
    if( addrBAelems != NULL ) {
        (*env)->ReleaseByteArrayElements(env, addrBA, addrBAelems, JNI_ABORT);
    }
}

/*
 * SSLServerSocket and SSLSocket have their own synchronization 
 * that protects SocketBase.socketClose.
 */
JNIEXPORT void JNICALL
Java_org_mozilla_jss_ssl_SocketBase_socketClose(JNIEnv *env, jobject self)
{
    JSSL_SocketData *sock = NULL;

    /* get the FD */
    if( JSSL_getSockData(env, self, &sock) != PR_SUCCESS) {
        /* exception was thrown */
        return;
    }

    JSSL_DestroySocketData(env, sock);
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_ssl_SocketBase_requestClientAuthNoExpiryCheckNative
    (JNIEnv *env, jobject self, jboolean b)
{
    JSSL_SocketData *sock = NULL;
    SECStatus status;

    if( JSSL_getSockData(env, self, &sock) != PR_SUCCESS) goto finish;

    /*
     * Set the option on the socket
     */
    status = SSL_OptionSet(sock->fd, SSL_REQUEST_CERTIFICATE, b);
    if( status != SECSuccess ) {
        JSSL_throwSSLSocketException(env,
            "Failed to set REQUEST_CERTIFICATE option on socket");
        goto finish;
    }

    if(b) {
        /*
         * Set the callback function
         */
        status = SSL_AuthCertificateHook(sock->fd,
                        JSSL_ConfirmExpiredPeerCert, NULL /*cx*/);
        if( status != SECSuccess ) {
            JSSL_throwSSLSocketException(env,
                "Failed to set certificate authentication callback");
            goto finish;
        }
    }

finish:
    EXCEPTION_CHECK(env, sock)
    return;
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_ssl_SocketBase_setSSLOption
    (JNIEnv *env, jobject self, jint option, jint on)
{
    SECStatus status;
    JSSL_SocketData *sock = NULL;

    /* get my fd */
    if( JSSL_getSockData(env, self, &sock) != PR_SUCCESS ) {
        goto finish;
    }

    /* set the option */
    status = SSL_OptionSet(sock->fd, JSSL_enums[option], on);
    if( status != SECSuccess ) {
        JSSL_throwSSLSocketException(env, "SSL_OptionSet failed");
        goto finish;
    }

finish:
    EXCEPTION_CHECK(env, sock)
    return;
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_ssl_SocketBase_setSSLOptionMode
    (JNIEnv *env, jobject self, jint option, jint mode)
{
    SECStatus status;
    JSSL_SocketData *sock = NULL;

    /* get my fd */
    if( JSSL_getSockData(env, self, &sock) != PR_SUCCESS ) {
        goto finish;
    }

    /* set the option */
    status = SSL_OptionSet(sock->fd, JSSL_enums[option], JSSL_enums[mode]);
    if( status != SECSuccess ) {
        JSSL_throwSSLSocketException(env, "SSL_OptionSet failed");
        goto finish;
    }

finish:
    EXCEPTION_CHECK(env, sock)
    return;
}


JNIEXPORT jint JNICALL
Java_org_mozilla_jss_ssl_SocketBase_getSSLOption(JNIEnv *env,
                                        jobject self, jint option)
{
    JSSL_SocketData *sock = NULL;
    SECStatus status = SECSuccess;
    PRBool bOption = PR_FALSE;

    if( JSSL_getSockData(env, self, &sock) != PR_SUCCESS ) {
        goto finish;
    }

    /* get the option */
    status = SSL_OptionGet(sock->fd, JSSL_enums[option], &bOption);
    if( status != SECSuccess ) {
        JSSL_throwSSLSocketException(env, "SSL_OptionGet failed");
        goto finish;
    }

    
finish:
    EXCEPTION_CHECK(env, sock)
    return bOption;
}

PRStatus
JSSL_getSockAddr
    (JNIEnv *env, jobject self, PRNetAddr *addr, LocalOrPeer localOrPeer)
{
    JSSL_SocketData *sock = NULL;
    PRStatus status=PR_FAILURE;

    /* get my fd */
    if( JSSL_getSockData(env, self, &sock) != PR_SUCCESS ) {
        goto finish;
    }

    /* get the port */
    if( localOrPeer == LOCAL_SOCK ) {
        status = PR_GetSockName(sock->fd, addr);
    } else {
        PR_ASSERT( localOrPeer == PEER_SOCK );
        status = PR_GetPeerName(sock->fd, addr);
    }
    if( status != PR_SUCCESS ) {
        JSSL_throwSSLSocketException(env, "PR_GetSockName failed");
    }

finish:
    EXCEPTION_CHECK(env, sock)
    return status;
}

JNIEXPORT jbyteArray JNICALL
Java_org_mozilla_jss_ssl_SocketBase_getPeerAddressByteArrayNative
    (JNIEnv *env, jobject self)
{
    jbyteArray byteArray=NULL;
    PRNetAddr addr;
    jbyte *address=NULL;
    int size=4;

    if( JSSL_getSockAddr(env, self, &addr, PEER_SOCK) != PR_SUCCESS) {
        goto finish;
    }

    if( PR_NetAddrFamily(&addr) ==  PR_AF_INET6) {
        size = 16;
        address = (jbyte *) &addr.ipv6.ip;
    } else {
        address = (jbyte *) &addr.inet.ip;
    }

    byteArray = (*env)->NewByteArray(env,size);
    if(byteArray == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }
    (*env)->SetByteArrayRegion(env, byteArray, 0,size ,address);
    if( (*env)->ExceptionOccurred(env) != NULL) {
        PR_ASSERT(PR_FALSE);
        goto finish;
    }

finish:
    return byteArray;
}

JNIEXPORT jbyteArray JNICALL
Java_org_mozilla_jss_ssl_SocketBase_getLocalAddressByteArrayNative
    (JNIEnv *env, jobject self)
{
    jbyteArray byteArray=NULL;
    PRNetAddr addr;
    jbyte *address=NULL;
    int size=4;

    if( JSSL_getSockAddr(env, self, &addr, LOCAL_SOCK) != PR_SUCCESS) {
        goto finish;
    }

    if( PR_NetAddrFamily(&addr) ==  PR_AF_INET6) {
        size = 16;
        address = (jbyte *) &addr.ipv6.ip;
    } else {
        address = (jbyte *) &addr.inet.ip;
    }

    byteArray = (*env)->NewByteArray(env,size);
    if(byteArray == NULL) {
        ASSERT_OUTOFMEM(env);
        goto finish;
    }
    (*env)->SetByteArrayRegion(env, byteArray, 0,size,address);
    if( (*env)->ExceptionOccurred(env) != NULL) {
        PR_ASSERT(PR_FALSE);
        goto finish;
    }

finish:
    return byteArray;
}

/* Leave the original versions of these functions for compatibility */

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_ssl_SocketBase_getPeerAddressNative
    (JNIEnv *env, jobject self)
{
    PRNetAddr addr;

    if( JSSL_getSockAddr(env, self, &addr, PEER_SOCK) == PR_SUCCESS) {
        return ntohl(addr.inet.ip);
    } else {
        return 0;
    }
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_ssl_SocketBase_getLocalAddressNative(JNIEnv *env,
    jobject self)
{
    PRNetAddr addr;

    if( JSSL_getSockAddr(env, self, &addr, LOCAL_SOCK) == PR_SUCCESS ) {
        return ntohl(addr.inet.ip);
    } else {
        return 0;
    }
}

JNIEXPORT jint JNICALL
Java_org_mozilla_jss_ssl_SocketBase_getLocalPortNative(JNIEnv *env,
    jobject self)
{
    PRNetAddr addr;

    if( JSSL_getSockAddr(env, self, &addr, LOCAL_SOCK) == PR_SUCCESS ) {
        return ntohs(addr.inet.port);
    } else {
        return 0;
    }
}

/*
 * This is here for backwards binary compatibility: I didn't want to remove
 * the symbol from the DLL. This would only get called if someone were using
 * a pre-3.2 version of the JSS classes with this post-3.2 library. Using
 * different versions of the classes and the C code is not supported.
 */
JNIEXPORT void JNICALL
Java_org_mozilla_jss_ssl_SocketBase_setClientCertNicknameNative(
    JNIEnv *env, jobject self, jstring nick)
{
    PR_ASSERT(0);
    JSS_throwMsg(env, SOCKET_EXCEPTION, "JSS JAR/DLL mismatch");
}

JNIEXPORT void JNICALL
Java_org_mozilla_jss_ssl_SocketBase_setClientCert(
    JNIEnv *env, jobject self, jobject certObj)
{
    JSSL_SocketData *sock = NULL;
    SECStatus status;
    CERTCertificate *cert = NULL;
    PK11SlotInfo *slot = NULL;

    if( certObj == NULL ) {
        JSS_throw(env, NULL_POINTER_EXCEPTION);
        goto finish;
    }

    if( JSSL_getSockData(env, self, &sock) != PR_SUCCESS) goto finish;

    /*
     * Store the cert and slot in the SocketData.
     */
    if( JSS_PK11_getCertPtr(env, certObj, &cert) != PR_SUCCESS ) {
        goto finish;
    }
    if( JSS_PK11_getCertSlotPtr(env, certObj, &slot) != PR_SUCCESS ) {
        goto finish;
    }
    if( sock->clientCert != NULL ) {
        CERT_DestroyCertificate(sock->clientCert);
    }
    if( sock->clientCertSlot != NULL ) {
        PK11_FreeSlot(sock->clientCertSlot);
    }
    sock->clientCert = CERT_DupCertificate(cert);
    sock->clientCertSlot = PK11_ReferenceSlot(slot);

    /*
     * Install the callback.
     */
    status = SSL_GetClientAuthDataHook(sock->fd, JSSL_GetClientAuthData,
                    (void*)sock);
    if(status != SECSuccess) {
        JSSL_throwSSLSocketException(env,
            "Unable to set client auth data hook");
        goto finish;
    }

finish:
    EXCEPTION_CHECK(env, sock)
}

void
JSS_SSL_processExceptions(JNIEnv *env, PRFilePrivate *priv)
{
    jthrowable currentExcep;

    if( priv == NULL ) {
        return;
    }

    currentExcep = (*env)->ExceptionOccurred(env);
    (*env)->ExceptionClear(env);

    if( currentExcep != NULL ) {
        jmethodID processExcepsID;
        jclass socketBaseClass;
        jthrowable newException;

        socketBaseClass = (*env)->FindClass(env, SOCKET_BASE_NAME);
        if( socketBaseClass == NULL ) {
            ASSERT_OUTOFMEM(env);
            goto finish;
        }
        processExcepsID = (*env)->GetStaticMethodID(env, socketBaseClass,
            PROCESS_EXCEPTIONS_NAME, PROCESS_EXCEPTIONS_SIG);
        if( processExcepsID == NULL ) {
            ASSERT_OUTOFMEM(env);
            goto finish;
        }

        newException = (*env)->CallStaticObjectMethod(env, socketBaseClass,
            processExcepsID, currentExcep, JSS_SSL_getException(priv));

        if( newException == NULL ) {
            ASSERT_OUTOFMEM(env);
            goto finish;
        }
        currentExcep = newException;
    } else {
        jthrowable excep = JSS_SSL_getException(priv);
        PR_ASSERT( excep == NULL );
        if( excep != NULL ) {
            (*env)->DeleteGlobalRef(env, excep);
        }
    }

finish:
    if( currentExcep != NULL && (*env)->ExceptionOccurred(env) == NULL) {
        int VARIABLE_MAY_NOT_BE_USED ret = (*env)->Throw(env, currentExcep);
        PR_ASSERT(ret == 0);
    }
}
