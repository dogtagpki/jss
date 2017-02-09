/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.ssl;

import java.util.*;
import java.net.InetAddress;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.TokenException;

/**
 * SSL server socket.
 */
public class SSLServerSocket extends java.net.ServerSocket {

    /*
     * Locking rules of SSLServerSocket
     *
     * isClosed and inAccept must be accessed with the object locked.
     *
     * acceptLock must be locked throughout the accept method.  It is
     * used to serialize accept calls on the object.
     */

    private SocketProxy sockProxy = null;
    private boolean handshakeAsClient = false;
    private SocketBase base = new SocketBase();
    private boolean isClosed = false;
    private boolean inAccept = false;
    private java.lang.Object acceptLock = new java.lang.Object();

    /**
     * The default size of the listen queue.
     */
    public static final int DEFAULT_BACKLOG = 50;

    /**
     * Creates a server socket listening on the given port.
     * The listen queue will be of size DEFAULT_BACKLOG.
     */
    public SSLServerSocket(int port) throws IOException {
        this(port, DEFAULT_BACKLOG, null);
    }

    /**
     * Creates a server socket listening on the given port.
     * @param backlog The size of the socket's listen queue.
     */
    public SSLServerSocket(int port, int backlog) throws IOException {
        this(port, backlog, null);
    }

    /**
     * Creates a server socket listening on the given port.
     * @param backlog The size of the socket's listen queue.
     * @param bindAddr The local address to which to bind. If null, an
     *      unspecified local address will be bound to.
     */
    public SSLServerSocket(int port, int backlog, InetAddress bindAddr)
        throws IOException
    {
        this(port, backlog, bindAddr, null);
    }

    /**
     * Creates a server socket listening on the given port.
     * @param backlog The size of the socket's listen queue.
     * @param bindAddr The local address to which to bind. If null, an
     *      unspecified local address will be bound to.
     * @param certApprovalCallback Will get called to approve any certificate
     *      presented by the client.
     */
    public SSLServerSocket(int port, int backlog, InetAddress bindAddr,
                SSLCertificateApprovalCallback certApprovalCallback)
        throws IOException
    {
        this(port,backlog, bindAddr, certApprovalCallback, false);
    }

    /**
     * Creates a server socket listening on the given port.
     * @param backlog The size of the socket's listen queue.
     * @param bindAddr The local address to which to bind. If null, an
     *      unspecified local address will be bound to.
     * @param certApprovalCallback Will get called to approve any certificate
     *      presented by the client.
     * @param reuseAddr Reuse the local bind port; this parameter sets
     *      the <tt>SO_REUSEADDR</tt> option on the socket before calling
     *      <tt>bind()</tt>. The default is <tt>false</tt> for backward
     *      compatibility.
     */
    public SSLServerSocket(int port, int backlog, InetAddress bindAddr,
                SSLCertificateApprovalCallback certApprovalCallback,
                boolean reuseAddr)
        throws IOException
    {
        // Dance the dance of fools.  The superclass doesn't have a default
        // constructor, so we have to trick it here. This is an example
        // of WHY WE SHOULDN'T BE EXTENDING SERVERSOCKET.
        super(0);
        super.close();

        // create the socket

        int socketFamily = SocketBase.SSL_AF_INET;
        if(SocketBase.supportsIPV6()) {
            socketFamily = SocketBase.SSL_AF_INET6;
        }

        sockProxy = new SocketProxy(
            base.socketCreate(this, certApprovalCallback, null,socketFamily) );

        base.setProxy(sockProxy);

        setReuseAddress(reuseAddr);

        byte[] bindAddrBA = null;
        if( bindAddr != null ) {
            bindAddrBA = bindAddr.getAddress();
        }
        base.socketBind(bindAddrBA, port);

        String hostName = null;
        if(bindAddr != null)  {
            hostName = bindAddr.getCanonicalHostName();
        }
        socketListen(backlog);
    }

    private native void socketListen(int backlog) throws SocketException;

    /**
     * Accepts a connection. This call will block until a connection is made
     * or the timeout is reached.
     *
     * @return java.net.Socket Local socket for client communication
     *
     * @throws IOException  If an input or output exception occurred
     * @throws SocketTimeoutException  If the socket times out trying to connect
     * @throws SSLSocketException  JSS subclass of java.net.SocketException
     */
    public Socket accept() throws IOException {
        synchronized (acceptLock) {
            synchronized (this) {
                if (isClosed) {
                    throw new IOException(
                    "SSLServerSocket has been closed, and cannot be reused.");
                }
                inAccept = true;
            }
            SSLSocket s = new SSLSocket();
            try {
                /*
                 * socketAccept can throw an exception for timeouts,
                 * IO errors, or PR_Interrupt called by abortAccept.
                 * So first get a socket pointer, and if successful
                 * create the SocketProxy.
                 */
                byte[] socketPointer = null;
                socketPointer = socketAccept(s, base.getTimeout(),
                    handshakeAsClient);
                SocketProxy sp = new SocketProxy(socketPointer);
                s.setSockProxy(sp);
            } finally {
                synchronized (this) {
                    inAccept=false;
                }
            }
            return s;
        }
    }

    /**
     * Sets the SO_TIMEOUT socket option.
     * @param timeout The timeout time in milliseconds.
     */
    public void setSoTimeout(int timeout) {
        base.setTimeout(timeout);
    }

    /**
     * Returns the current value of the SO_TIMEOUT socket option.
     * @return The timeout time in milliseconds.
     */
    public int getSoTimeout() {
        return base.getTimeout();
    }

    public native void setReuseAddress(boolean reuse) throws SocketException;
    public native boolean getReuseAddress() throws SocketException;
    private native void abortAccept() throws SocketException;
    private native byte[] socketAccept(SSLSocket s, int timeout,
        boolean handshakeAsClient)
        throws SocketException, SocketTimeoutException;

    /**
     * Empties the SSL client session ID cache.
     */
    public static native void clearSessionCache();

    protected void finalize() throws Throwable {
        close(); /* in case user never called close */
    }


    /**
     * @return The local port.
     */
    public int getLocalPort() {
        return base.getLocalPort();
    }

    /**
     * Closes this socket.
     */
    public void close() throws IOException {
        synchronized (this) {
            if( isClosed ) {
                /* finalize calls close or user calls close more than once */
                return;
            }
            isClosed = true;
            if( sockProxy == null ) {
                /* nothing to do */
                return;
            }
            if( inAccept ) {
                abortAccept();
            }
        }
        /* Lock acceptLock to ensure that accept has been aborted. */
        synchronized (acceptLock) {
            base.close();
            sockProxy = null;
            base.setProxy(null);
        }
    }

    // This directory is used as the default for the Session ID cache
    private final static String UNIX_TEMP_DIR = "/tmp";
    private final static String WINDOWS_TEMP_DIR = "\\temp";

    /**
     * Configures the session ID cache.
     * @param maxSidEntries The maximum number of entries in the cache. If
     *  0 is passed, the default of 10,000 is used.
     * @param ssl2EntryTimeout The lifetime in seconds of an SSL2 session.
     *  The minimum timeout value is 5 seconds and the maximum is 24 hours.
     *  Values outside this range are replaced by the server default value
     *  of 100 seconds.
     * @param ssl3EntryTimeout The lifetime in seconds of an SSL3 session.
     *  The minimum timeout value is 5 seconds and the maximum is 24 hours.
     *  Values outside this range are replaced by the server default value
     *  of 100 seconds.
     * @param cacheFileDirectory The pathname of the directory that
     *  will contain the session cache. If null is passed, the server default
     *  is used: <code>/tmp</code> on Unix and <code>\\temp</code> on Windows.
     */
    public static native void configServerSessionIDCache(int maxSidEntries,
        int ssl2EntryTimeout, int ssl3EntryTimeout, String cacheFileDirectory)
        throws SocketException;

    /**
     * Sets the certificate to use for server authentication.
     */
    public void setServerCertNickname(String nick) throws SocketException
    {
      try {
        setServerCert( CryptoManager.getInstance().findCertByNickname(nick) );
      } catch(CryptoManager.NotInitializedException nie) {
        throw new SocketException("CryptoManager not initialized");
      } catch(ObjectNotFoundException onfe) {
        throw new SocketException("Object not found: " + onfe);
      } catch(TokenException te) {
        throw new SocketException("Token Exception: " + te);
      }
    }

    /**
     * Sets the certificate to use for server authentication.
     */
    public native void setServerCert(
        org.mozilla.jss.crypto.X509Certificate certnickname)
        throws SocketException;

    /**
     * Enables/disables the request of client authentication. This is only
     *  meaningful for the server end of the SSL connection. During the next
     *  handshake, the remote peer will be asked to authenticate itself.
     * @see org.mozilla.jss.ssl.SSLServerSocket#requireClientAuth
     */
    public void requestClientAuth(boolean b) throws SocketException {
        base.requestClientAuth(b);
    }

    /**
     * @deprecated As of JSS 3.0. This method is misnamed. Use
     *  <code>requestClientAuth</code> instead.
     */
    public void setNeedClientAuth(boolean b) throws SocketException {
        base.requestClientAuth(b);
    }

    /**
     * Enables/disables the request of client authentication. This is only
     *  meaningful for the server end of the SSL connection. During the next
     *  handshake, the remote peer will be asked to authenticate itself.
     *  <p>In addition, the client certificate's expiration will not
     *  prevent it from being accepted.
     * @see org.mozilla.jss.ssl.SSLServerSocket#requireClientAuth
    public void requestClientAuthNoExpiryCheck(boolean b)
        throws SocketException
    {
        base.requestClientAuthNoExpiryCheck(b);
    }

    /**
     * @deprecated As of JSS 3.0. This method is misnamed. Use
     *  <code>requestClientAuthNoExpiryCheck</code> instead.
     */
    public void setNeedClientAuthNoExpiryCheck(boolean b)
        throws SocketException
    {
        base.requestClientAuthNoExpiryCheck(b);
    }

    /**
     * Enables SSL v2 on this socket. It is enabled  by default, unless the
     * default has been changed with <code>SSLSocket.enableSSL2Default</code>.
     */
    public void enableSSL2(boolean enable) throws SocketException {
        base.enableSSL2(enable);
    }

    /**
     * Enables SSL v3 on this socket. It is enabled by default, unless the
     * default has been changed with <code>SSLSocket.enableSSL3Default</code>.
     */
    public void enableSSL3(boolean enable) throws SocketException {
        base.enableSSL3(enable);
    }

    /**
     * Enables TLS on this socket. It is enabled by default, unless the
     * default has been changed with <code>SSLSocket.enableTLSDefault</code>.
     */
    public void enableTLS(boolean enable) throws SocketException {
        base.enableTLS(enable);
    }

    /**
     * Enables Session tickets on this socket. It is disabled by default,
     * unless the default has been changed with
     * <code>SSLSocket.enableSessionTicketsDefault</code>.
     */
    public void enableSessionTickets(boolean enable) throws SocketException {
        base.enableSessionTickets(enable);
    }

    /**
     * Enables the mode of renegotiation that the peer must use.
     * The default is never renegotiate at all unless the default
     * has been changed with <code>SSLSocket.enableRenegotiationDefault</code>.
     *
     *  @param mode One of:
     *      SSLSocket.SSL_RENEGOTIATE_NEVER - Never renegotiate at all.
     *
     *      SSLSocket.SSL_RENEGOTIATE_UNRESTRICTED - Renegotiate without
     *      restriction, whether or not the peer's hello bears the TLS
     *      renegotiation info extension. Vulnerable, as in the past.
     *
     *      SSLSocket.SSL_RENEGOTIATE_REQUIRES_XTN -  Only renegotiate if the
     *      peer's hello bears the TLS renegotiation_info extension. This is
     *      safe renegotiation.
     *
     *      SSLSocket.SSL_RENEGOTIATE_TRANSITIONAL - Disallow unsafe
     *      renegotiation in server sockets only, but allow clients
     *      to continue to renegotiate with vulnerable servers.
     *      This value should only be used during the transition period
     *      when few servers have been upgraded.
     */

    public void enableRenegotiation(int mode)
            throws SocketException
    {
        if (mode >= SocketBase.SSL_RENEGOTIATE_NEVER &&
            mode <= SocketBase.SSL_RENEGOTIATE_TRANSITIONAL) {
            base.enableRenegotiation(mode);
        } else {
            throw new SocketException("Incorrect input value.");
        }
     }

    /**
     * For this socket require that the peer must send
     * Signaling Cipher Suite Value (SCSV) or Renegotiation Info (RI)
     * extension in ALL handshakes. It is disabled by default,
     * unless the default has been changed with
     * <code>SSLSocket.enableRequireSafeNegotiationDefault</code>.
     */
    public void enableRequireSafeNegotiation(boolean enable)
            throws SocketException {
        base.enableRequireSafeNegotiation(enable);
    }

    /**
     * Enable rollback detection for this socket.
     * It is enabled by default, unless the default has been changed
     * with <code>SSLSocket.enableRollbackDetectionDefault</code>.
     */
    public void enableRollbackDetection(boolean enable) throws SocketException {
        base.enableRollbackDetection(enable);
    }

    /**
     * This option, enableStepDown, is concerned with the generation
     * of step-down keys which are used with export suites.
     * If the server cert's public key is 512 bits or less,
     * this option is ignored because step-down keys don't
     * need to be generated.
     * If the server cert's public key is more than 512 bits,
     * this option has the following effect:
     * enable=true:  generate step-down keys
     * enable=false: don't generate step-down keys; disable
     * export cipher suites
     *
     * This option is enabled by default; unless the default has
     * been changed with <code>SSLSocket.enableStepDownDefault</code>.
     */
    public void enableStepDown(boolean enable) throws SocketException {
        base.enableStepDown(enable);
    }

    /**
     * Enable simultaneous read/write by separate read and write threads
     * (full duplex) for this socket.
     * It is disabled by default, unless the default has been changed
     * with <code>SSLSocket.enableFDXDefault</code>.
     */
    public void enableFDX(boolean enable) throws SocketException {
        base.enableFDX(enable);
    }

    /**
     * Enable sending v3 client hello in v2 format for this socket.
     * It is enabled by default, unless the default has been changed
     * with <code>SSLSocket.enableV2CompatibleHelloDefault</code>.
     */
    public void enableV2CompatibleHello(boolean enable) throws SocketException {
        base.enableV2CompatibleHello(enable);
    }

    /**
     * @return a String listing  the current SSLOptions for this socket.
     */
    public String getSSLOptions() {
        return base.getSSLOptions();
    }

    /**
     * @return the local address of this server socket.
     */
    public InetAddress getInetAddress() {
        return base.getLocalAddress();
    }

    /**
     * Sets whether the socket requires client authentication from the remote
     *  peer. If requestClientAuth() has not already been called, this
     *  method will tell the socket to request client auth as well as requiring
     *  it.
     * @deprecated use requireClientAuth(int)
     */
    public void requireClientAuth(boolean require, boolean onRedo)
            throws SocketException
    {
        base.requireClientAuth(require, onRedo);
    }

    /**
     * Sets whether the socket requires client authentication from the remote
     *  peer. If requestClientAuth() has not already been called, this
     *  method will tell the socket to request client auth as well as requiring
     *  it.
     *  @param mode One of:  SSLSocket.SSL_REQUIRE_NEVER,
     *                       SSLSocket.SSL_REQUIRE_ALWAYS,
     *                       SSLSocket.SSL_REQUIRE_FIRST_HANDSHAKE,
     *                       SSLSocket.SSL_REQUIRE_NO_ERROR
     */

    public void requireClientAuth(int mode)
            throws SocketException
    {
        if (mode >= SocketBase.SSL_REQUIRE_NEVER &&
            mode <= SocketBase.SSL_REQUIRE_NO_ERROR) {
            base.requireClientAuth(mode);
        } else {
            throw new SocketException("Incorrect input value.");
        }
     }


    /**
     * Sets the nickname of the certificate to use for client authentication.
     */
    public void setClientCertNickname(String nick) throws SocketException {
        base.setClientCertNickname(nick);
    }

    /**
     * Sets the certificate to use for client authentication.
     */
    public void setClientCert(org.mozilla.jss.crypto.X509Certificate cert)
        throws SocketException
    {
        base.setClientCert(cert);
    }

    /**
     * Determines whether this end of the socket is the client or the server
     *  for purposes of the SSL protocol. By default, it is the server.
     * @param b true if this end of the socket is the SSL slient, false
     *      if it is the SSL server.
     */
    public void setUseClientMode(boolean b) {
        handshakeAsClient = b;
    }

    /**
     * Enables/disables the session cache. By default, the session cache
     * is enabled.
     */
    public void useCache(boolean b) throws SocketException {
        base.useCache(b);
    }

    /**
     * Returns the addresses and ports of this socket
     * or an error message if the socket is not in a valid state.
     */
    public String toString() {

        try {
            InetAddress inetAddr  = getInetAddress();
            int localPort         = getLocalPort();
            StringBuffer buf      = new StringBuffer();
            buf.append("SSLServerSocket[addr=");
            buf.append(inetAddr);
            buf.append(",localport=");
            buf.append(localPort);
            buf.append("]");
            return buf.toString();
        } catch (Exception e) {
            return "Exception caught in toString(): " + e.getMessage();
        }
    }
}
