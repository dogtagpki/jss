package org.mozilla.jss.ssl.javax;

import java.io.*;
import java.net.*;
import java.nio.channels.*;
import java.security.*;
import java.util.*;
import javax.net.ssl.*;

import org.mozilla.jss.pkcs11.PK11Cert;
import org.mozilla.jss.pkcs11.PK11PrivKey;
import org.mozilla.jss.provider.javax.crypto.JSSKeyManager;
import org.mozilla.jss.provider.javax.crypto.JSSTrustManager;

/**
 * SSL-enabled socket following the javax.net.ssl.SSLSocket interface.
 *
 * Most users will want to use the JSSSocketFactory provided by the Java
 * Provider interface instead of using this class directly.
 *
 * This SSLSocket implementation is a wrapped implementation. In particular, we
 * need to consume an existing Socket (via the consumeSocket(...) call) which
 * we actually send data over. When called from a socket factory, this
 * additional socket will be automatically created for the caller. This
 * is necessary because SSLSocketFactory includes a mode which wraps an
 * existing socket.
 *
 * All JSSSocket instances have a underlying SocketChannel, of type
 * JSSSocketChannel. Notably lacking is a javax.net.ssl.SSLSocketChannel type,
 * so JSSSocketChannel includes no additional SSL-specific options. However,
 * the core of the SSLEngine wrapping logic exists there.
 *
 * In order to interoperate with JSSEngine, many of the adjacent methods have
 * been included in this class as well.
 *
 * This socket can either be a client or a server, depending on how it was
 * created. For more information, see the javax.net.ssl.SSLSocket
 * documentation.
 *
 * To construct a (useful) new instance, the following calls must be made:
 *
 * - new JSSSocket();
 * - consumeSocket(inst);
 * - initSSLEngine(...);
 * - setKeyManagers(...);
 * - setTrustManagers(...);
 *
 * Optionally, setSSLContext(...) could be called to provide the SSLContext
 * from which the SSLEngine should be constructed. This should be called prior
 * to initSSLEngine(...) being called.
 */
public class JSSSocket extends SSLSocket {
    /**
     * Name of the SSLEngine protocol to use.
     */
    private String engineProviderProtocol = "TLS";

    /**
     * Name of the SSLEngine provider to use.
     */
    private String engineProvider = "Mozilla-JSS";

    /**
     * SSLContext to use to create the JSSEngine. Note that JSSSocket will fail
     * if the context doesn't create JSSEngine instances.
     */
    private SSLContext jssContext;

    /**
     * JSSEngine instance to utilize for SSLEngine operations.
     */
    private JSSEngine engine;

    /**
     * All registered handshake callbacks.
     */
    private ArrayList<HandshakeCompletedListener> handshakeCallbacks = new ArrayList<HandshakeCompletedListener>();

    /**
     * The socket this JSSSocket was created over; all read/write operations
     * go through this socket and all information exposed via Socket members
     * go through here.
     */
    private Socket parent;

    /**
     * Previously consumed data, if any; utilized for certain SSLSocketFactory
     * calls.
     */
    private InputStream consumedData;

    /**
     * Underlying SocketChannel for this socket; always exists.
     */
    private JSSSocketChannel channel;

    /**
     * Whether or not to automatically close the underlying Socket when this
     * socket has been closed; defaults to true.
     */
    private boolean autoClose = true;

    /**
     * Whether or not this socket has been closed.
     */
    private boolean closed;

    /**
     * Start building a new JSSSocket.
     *
     * We specifically avoid creating any other constructors as we wish to
     * consume an existing socket rather than creating a new one.
     */
    public JSSSocket() {}

    /**
     * Consume a parent socket, utilizing it for all read/write operations.
     *
     * This JSSSocket instance will inherit all information about the
     * connection from this underlying socket. When utilized in a JSSSocket,
     * callers should refrain from interacting with the underlying socket
     * directly until the TLS connection is closed. Otherwise, messages may
     * get dropped.
     */
    public void consumeSocket(Socket parent) throws IOException {
        if (parent == null) {
            String msg = "Unable to consume and utilize null parent socket!";
            throw new IOException(msg);
        }

        if (closed) {
            String msg = "Unable to perform operations on a closed socket!";
            throw new IOException(msg);
        }

        this.parent = parent;
    }

    /**
     * Get the SSLContext if one exists or create a new instance.
     *
     * This is used by initSSLEngine(..) to create the underlying SSLEngine.
     */
    protected SSLContext getSSLContext() throws IOException {
        if (closed) {
            String msg = "Unable to perform operations on a closed socket!";
            throw new IOException(msg);
        }

        if (jssContext == null) {
            try {
                jssContext = SSLContext.getInstance(engineProviderProtocol, engineProvider);
            } catch (Exception e) {
                String msg = "Unable to create JSSSocket prior to Mozilla-JSS ";
                msg += "initialization! " + e.getMessage();
                throw new IOException(msg, e);
            }
        }

        return jssContext;
    }

    /**
     * Explicitly set the SSLContext utilized by this JSSSocket instance.
     *
     * This enables JSSServerSocket to copy its SSLContext over to the accepted
     * JSSSocket.
     */
    public void setSSLContext(SSLContext ctx) throws IOException {
        jssContext = ctx;
    }

    /**
     * Initialize the underlying SocketChannel.
     */
    private void init() throws IOException {
        if (closed) {
            String msg = "Unable to perform operations on a closed socket!";
            throw new IOException(msg);
        }

        if (engine == null) {
            initEngine();
        }

        SocketChannel parentChannel = parent.getChannel();

        if (parentChannel == null) {
            ReadableByteChannel read = Channels.newChannel(parent.getInputStream());
            WritableByteChannel write = Channels.newChannel(parent.getOutputStream());

            channel = new JSSSocketChannel(this, parent, read, write, engine);
        } else {
            channel = new JSSSocketChannel(this, parentChannel, engine);
        }

        channel.setConsumedData(consumedData);
        channel.setAutoClose(autoClose);
    }

    /**
     * Explicitly initialize the SSLEngine with no session resumption
     * information.
     */
    public void initEngine() throws IOException {
        engine = (JSSEngine) getSSLContext().createSSLEngine();
    }

    /**
     * Explicitly initialize the SSLEngine with information for session
     * resumption, including peer's hostname and port.
     */
    public void initEngine(String host, int port) throws IOException {
        engine = (JSSEngine) getSSLContext().createSSLEngine(host, port);
    }

    /**
     * Get the underlying JSSEngine instance.
     *
     * Note that, just like accessing the underlying Socket instance while the
     * JSSSocket instance is still open is dangerous, performing other TLS
     * operations directly via JSSEngine is also dangerous. This is mostly
     * exposed to enable advanced configuration of the JSSEngine that isn't
     * otherwise allowed by JSSSocket, and to facilitate the accept() method
     * on JSSServerSocket.
     */
    public JSSEngine getEngine() {
        return engine;
    }

    /**
     * Get the underlying SocketChannel for this Socket.
     *
     * @see java.net.Socket#getChannel()
     */
    public JSSSocketChannel getChannel() {
        if (parent.getChannel() == null) {
            return null;
        }

        return getInternalChannel();
    }

    /**
     * Helper to always return the channel for this socket,
     * initializing it if it isn't yet created.
     */
    protected JSSSocketChannel getInternalChannel() {
        if (channel == null) {
            try {
                init();
            } catch (IOException e) {
                throw new RuntimeException("Unexpected error trying to construct channel: " + e.getMessage(), e);
            }
        }

        return channel;
    }

    /**
     * Get a copy of an input stream for this Socket.
     *
     * @see java.net.Socket#getInputStream()
     */
    public InputStream getInputStream() throws IOException {
        if (channel == null) {
            init();
        }

        return Channels.newInputStream(channel);
    }

    /**
     * Get a copy of an output stream for this Socket.
     *
     * @see java.net.Socket#getOutputStream()
     */
    public OutputStream getOutputStream() throws IOException {
        if (channel == null) {
            init();
        }

        return Channels.newOutputStream(channel);
    }

    /**
     * Internal helper to perform the handshake operation, blocking.
     *
     * Note that JSSSocket doesn't invoke JSSEngine.wrap/unwrap directly;
     * instead everything is contained within JSSSocketChannel.
     */
    private void doHandshake() throws IOException {
        if (channel == null) {
            init();
        }

        boolean status = channel.finishConnect();
        if (!channel.isBlocking()) {
            // SSLSocket semantics explicitly say:
            //     > This method is synchronous for the initial handshake on
            //     > a connection and returns when the negotiated handshake is
            //     > complete.
            // so we have to block until the connection is complete. But use an
            // exponential backoff so we have a chance of catching any peer
            // data.
            int connectAttempts = 0;
            while (!status) {
                status = channel.finishConnect();

                try {
                    Thread.sleep(connectAttempts * 100);
                } catch (Exception e) {}

                connectAttempts += 1;
                if (connectAttempts > 25) {
                    break;
                }
            }
        }

        if (!status) {
            throw new IOException("Unable to finish handshake for an unknown reason.");
        }
    }

    /**
     * Helper to inform this socket of data already consumed from the wrapped
     * socket.
     *
     * This is provided to facilitate a SSLSocketFactory call which allows
     * construction of SSLSocket instances from a non-SSL ServerSocket,
     * allowing the application to check SNI information directly.
     */
    public void setConsumedData(InputStream consumed) {
        consumedData = consumed;
    }

    /**
     * Get the autoClose status of this socket, that is, whether or not its
     * parent socket will be automatically closed.
     */
    public boolean getAutoClose() {
        return autoClose;
    }

    /**
     * Set the autoClose status of this socket, that is, whether or not its
     * parent socket will be automatically closed.
     */
    public void setAutoClose(boolean on) {
        autoClose = on;

        // When the channel already exists, we need to propagate the status
        // to the channel as that actually handles closing this socket.
        if (channel != null) {
            channel.setAutoClose(on);
        }
    }

    /* == stubs over JSSEngine == */

    /**
     * Set the hostname this client socket is connecting to, for HTTPS TLS
     * certificate validation purposes.
     *
     * @see JSSEngine#setHostname(String)
     */
    public void setHostname(String name) {
        engine.setHostname(name);
    }

    /**
     * Set the certificate this SSLSocket will utilize from an alias in the
     * NSS DB.
     *
     * @see JSSEngine#setCertFromAlias(String)
     */
    public void setCertFromAlias(String alias) throws IllegalArgumentException {
        engine.setCertFromAlias(alias);
    }

    /**
     * Set the certificate this SSLSocket will utilize from a certificate and
     * its matching private key.
     *
     * @see JSSEngine#setKeyMaterials(PK11Cert, PK11PrivKey)
     */
    public void setKeyMaterials(PK11Cert our_cert, PK11PrivKey our_key) throws IllegalArgumentException {
        engine.setKeyMaterials(our_cert, our_key);
    }

    /**
     * Set the KeyManager this SSLSocket will utilize to select a key.
     *
     * @see JSSEngine#setKeyManager(X509KeyManager)
     */
    public void setKeyManager(X509KeyManager km) {
        engine.setKeyManager(km);
    }

    /**
     * Set the key managers this SSLSocket will utilize to select a key.
     *
     * @see JSSEngine#setKeyManagers(X509KeyManager[])
     */
    public void setKeyManagers(X509KeyManager[] xkms) {
        engine.setKeyManagers(xkms);
    }

    /**
     * Set the trust manager this SSLSocket will utilize to validate a peer's
     * certificate.
     *
     * @see JSSEngine#setTrustManager(JSSTrustManager)
     */
    public void setTrustManager(JSSTrustManager tm) {
        engine.setTrustManager(tm);
    }

    /**
     * Set the trust managers this SSLSocket will utilize to validate a peer's
     * certificate.
     *
     * @see JSSEngine#setTrustManagers(X509TrustManager[])
     */
    public void setTrustManagers(X509TrustManager[] xtms) {
        engine.setTrustManagers(xtms);
    }

    /* == stubs over SSLSocket == */

    /**
     * Begin a handshake, blocking to completion; this will begin a new
     * handshake when one has already been issued.
     *
     * @see JSSEngine#beginHandshake()
     * @see javax.net.ssl.SSLSocket#startHandshake()
     */
    @Override
    public void startHandshake() throws IOException {
        engine.beginHandshake();

        if (channel == null) {
            // Only be blocking on the first handshake call.
            doHandshake();
        }
    }

    /**
     * Add a callback to fire on handshake completion.
     *
     * @see javax.net.ssl.SSLSocket#addHandshakeCompletedListener(HandshakeCompletedListener)
     */
    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener callback) throws IllegalArgumentException {
        if (callback == null) {
            throw new IllegalArgumentException("Expected non-null HandshakeCompletedListener instance.");
        }

        handshakeCallbacks.add(callback);
    }

    /**
     * Internal helper to fire callbacks on handshake completion.
     */
    protected void notifyHandshakeCompletedListeners() {
        HandshakeCompletedEvent event = new HandshakeCompletedEvent(this, getSession());
        for (HandshakeCompletedListener callback : handshakeCallbacks) {
            callback.handshakeCompleted(event);
        }
    }

    /**
     * Remove a callback from firing on handshake completion.
     *
     * @see javax.net.ssl.SSLSocket#removeHandshakeCompletedListener(HandshakeCompletedListener)
     */
    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener callback) throws IllegalArgumentException {
        if (callback == null) {
            throw new IllegalArgumentException("Expected non-null HandshakeCompletedListener instance.");
        }

        if (!handshakeCallbacks.contains(callback)) {
            throw new IllegalArgumentException("Passed callback " + callback + " wasn't registered!");
        }

        handshakeCallbacks.remove(callback);
    }

    /**
     * Get the set of enabled cipher suites for this SSLSocket.
     *
     * @see JSSEngine#getEnabledCipherSuites()
     * @see javax.net.ssl.SSLSocket#getEnabledCipherSuites()
     */
    @Override
    public String[] getEnabledCipherSuites() {
        return engine.getEnabledCipherSuites();
    }

    /**
     * Get the set of supported cipher suites for this SSLSocket.
     *
     * @see JSSEngine#getSupportedCipherSuites()
     * @see javax.net.ssl.SSLSocket#getSupportedCipherSuites()
     */
    @Override
    public String[] getSupportedCipherSuites() {
        return engine.getSupportedCipherSuites();
    }

    /**
     * Set the list of enabled cipher suites for this SSLSocket.
     *
     * @see JSSEngine#setEnabledCipherSuites(String[])
     * @see javax.net.ssl.SSLSocket#setEnabledCipherSuites(String[])
     */
    @Override
    public void setEnabledCipherSuites(String[] suites) {
        engine.setEnabledCipherSuites(suites);
    }

    /**
     * Get the set of enabled protocol versions for this SSLSocket.
     *
     * @see JSSEngine#getEnabledProtocols()
     * @see javax.net.ssl.SSLSocket#getEnabledProtocols()
     */
    @Override
    public String[] getEnabledProtocols() {
        return engine.getEnabledProtocols();
    }

    /**
     * Get the set of supported protocol versions for this SSLSocket.
     *
     * @see JSSEngine#getSupportedProtocols()
     * @see javax.net.ssl.SSLSocket#getSupportedProtocols()
     */
    @Override
    public String[] getSupportedProtocols() {
        return engine.getSupportedProtocols();
    }

    /**
     * Set the list of enabled protocol versions for this SSLSocket.
     *
     * @see JSSEngine#setEnabledProtocols(String[])
     * @see javax.net.ssl.SSLSocket#setEnabledProtocols(String[])
     */
    @Override
    public void setEnabledProtocols(String[] protocols) {
        engine.setEnabledProtocols(protocols);
    }

    /**
     * Get whether or not this SSLSocket enables creation of new sessions.
     *
     * @see JSSEngine#getEnableSessionCreation()
     * @see javax.net.ssl.SSLSocket#getEnableSessionCreation()
     */
    @Override
    public boolean getEnableSessionCreation() {
        return engine.getEnableSessionCreation();
    }

    /**
     * Set whether or not this SSLSocket enables creation of new sessions.
     *
     * @see JSSEngine#setEnableSessionCreation(boolean)
     * @see javax.net.ssl.SSLSocket#setEnableSessionCreation(boolean)
     */
    @Override
    public void setEnableSessionCreation(boolean enabled) {
        engine.setEnableSessionCreation(enabled);
    }

    /**
     * Get the initial session constructed during handshaking.
     *
     * @see JSSEngine#getHandshakeSession()
     * @see javax.net.ssl.SSLSocket#getHandshakeSession()
     */
    @Override
    public SSLSession getHandshakeSession() {
        return engine.getHandshakeSession();
    }

    /**
     * Get the established session for this SSLSocket.
     *
     * @see JSSEngine#getSession()
     * @see javax.net.ssl.SSLSocket#getSession()
     */
    @Override
    public SSLSession getSession() {
        return engine.getSession();
    }

    /**
     * Get whether or not this SSLSocket is handshaking as a client.
     *
     * @see JSSEngine#getUseClientMode()
     * @see javax.net.ssl.SSLSocket#getUseClientMode()
     */
    @Override
    public boolean getUseClientMode() {
        return engine.getUseClientMode();
    }

    /**
     * Set whether or not this SSLSocket is handshaking as a client.
     *
     * @see JSSEngine#setUseClientMode(boolean)
     * @see javax.net.ssl.SSLSocket#setUseClientMode(boolean)
     */
    @Override
    public void setUseClientMode(boolean client) {
        engine.setUseClientMode(client);
    }

    /**
     * Get whether or not this SSLSocket wants client authentication.
     *
     * @see JSSEngine#getWantClientAuth()
     * @see javax.net.ssl.SSLSocket#getWantClientAuth()
     */
    @Override
    public boolean getWantClientAuth() {
        return engine.getWantClientAuth();
    }

    /**
     * Set whether or not this SSLSocket wants client authentication.
     *
     * @see JSSEngine#setWantClientAuth(boolean)
     * @see javax.net.ssl.SSLSocket#setWantClientAuth(boolean)
     */
    @Override
    public void setWantClientAuth(boolean want) {
        engine.setWantClientAuth(want);
    }

    /**
     * Get whether or not this SSLSocket needs client authentication.
     *
     * @see JSSEngine#getNeedClientAuth()
     * @see javax.net.ssl.SSLSocket#getNeedClientAuth()
     */
    @Override
    public boolean getNeedClientAuth() {
        return engine.getNeedClientAuth();
    }

    /**
     * Set whether or not this SSLSocket needs client authentication.
     *
     * @see JSSEngine#setNeedClientAuth(boolean)
     * @see javax.net.ssl.SSLSocket#setNeedClientAuth(boolean)
     */
    @Override
    public void setNeedClientAuth(boolean need) {
        engine.setNeedClientAuth(need);
    }

    /**
     * Get the configuration of this SSLSocket as a JSSParameters object.
     *
     * @see JSSEngine#getSSLParameters()
     * @see javax.net.ssl.SSLSocket#getSSLParameters()
     */
    @Override
    public JSSParameters getSSLParameters() {
        return engine.getSSLParameters();
    }

    /**
     * Set the configuration of this SSLSocket from the given SSLParameters
     * instance.
     *
     * @see JSSEngine#setSSLParameters(SSLParameters)
     * @see javax.net.ssl.SSLSocket#setSSLParameters(SSLParameters)
     */
    @Override
    public void setSSLParameters(SSLParameters params) {
        engine.setSSLParameters(params);
    }

    /* == stubs over Socket == */

    @Override
    public void connect(SocketAddress endpoint) throws IOException {
        parent.connect(endpoint);
    }

    @Override
    public void connect(SocketAddress endpoint, int timeout) throws IOException {
        parent.connect(endpoint, timeout);
    }

    @Override
    public void bind(SocketAddress bindpoint) throws IOException {
        parent.bind(bindpoint);
    }

    @Override
    public void close() throws IOException {
        getInternalChannel().close();
        engine.cleanup();
        engine = null;
        channel = null;
        closed = true;
    }

    @Override
    public void shutdownInput() throws IOException {
        getInternalChannel().shutdownInput();
    }

    @Override
    public void shutdownOutput() throws IOException {
        getInternalChannel().shutdownOutput();
    }

    @Override
    public InetAddress getInetAddress() {
        return parent.getInetAddress();
    }

    @Override
    public InetAddress getLocalAddress() {
        return parent.getLocalAddress();
    }

    @Override
    public int getPort() {
        return parent.getPort();
    }

    @Override
    public int getLocalPort() {
        return parent.getLocalPort();
    }

    @Override
    public SocketAddress getLocalSocketAddress() {
        return parent.getLocalSocketAddress();
    }

    @Override
    public SocketAddress getRemoteSocketAddress() {
        return parent.getRemoteSocketAddress();
    }

    @Override
    public boolean getTcpNoDelay() throws SocketException {
        return parent.getTcpNoDelay();
    }

    @Override
    public void setTcpNoDelay(boolean on) throws SocketException {
        parent.setTcpNoDelay(on);
    }

    @Override
    public int getSoLinger() throws SocketException {
        return parent.getSoLinger();
    }

    @Override
    public void setSoLinger(boolean on, int linger) throws SocketException {
        parent.setSoLinger(on, linger);
    }

    @Override
    public int getSoTimeout() throws SocketException {
        return parent.getSoTimeout();
    }

    @Override
    public void setSoTimeout(int timeout) throws SocketException {
        parent.setSoTimeout(timeout);
    }

    @Override
    public boolean getOOBInline() throws SocketException {
        return parent.getOOBInline();
    }

    @Override
    public void setOOBInline(boolean on) throws SocketException {
        parent.setOOBInline(on);
    }

    @Override
    public void sendUrgentData(int data) throws IOException {
        throw new IOException("Not implemented for SSLSockets!");
    }

    @Override
    public int getSendBufferSize() throws SocketException {
        return parent.getSendBufferSize();
    }

    @Override
    public void setSendBufferSize(int size) throws SocketException {
        parent.setSendBufferSize(size);
    }

    @Override
    public int getReceiveBufferSize() throws SocketException {
        return parent.getReceiveBufferSize();
    }

    @Override
    public void setReceiveBufferSize(int size) throws SocketException {
        parent.setReceiveBufferSize(size);
    }

    @Override
    public boolean getKeepAlive() throws SocketException {
        return parent.getKeepAlive();
    }

    @Override
    public void setKeepAlive(boolean on) throws SocketException {
        parent.setKeepAlive(on);
    }

    @Override
    public int getTrafficClass() throws SocketException {
        return parent.getTrafficClass();
    }

    @Override
    public void setTrafficClass(int tc) throws SocketException {
        parent.setTrafficClass(tc);
    }

    @Override
    public boolean getReuseAddress() throws SocketException {
        return parent.getReuseAddress();
    }

    @Override
    public void setReuseAddress(boolean on) throws SocketException {
        parent.setReuseAddress(on);
    }

    @Override
    public boolean isConnected() {
        return parent.isConnected();
    }

    @Override
    public boolean isBound() {
        return parent.isBound();
    }

    @Override
    public boolean isClosed() {
        return parent.isClosed();
    }

    @Override
    public boolean isInputShutdown() {
        return parent.isInputShutdown();
    }

    @Override
    public boolean isOutputShutdown() {
        return parent.isOutputShutdown();
    }

    @Override
    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
        parent.setPerformancePreferences(connectionTime, latency, bandwidth);
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("JSSSocket with ");
        builder.append(engine);
        builder.append(" over ");
        builder.append(parent);
        return builder.toString();
    }

    /* == stubs for Java 9 Socket == */

    public <T> Socket setOption(SocketOption<T> name, T value) throws IOException {
        getInternalChannel().setOption(name, value);
        return this;
    }

    public <T> T getOption(SocketOption<T> name) throws IOException {
        return getInternalChannel().getOption(name);
    }

    public Set<SocketOption<?>> supportedOptions() {
        return getInternalChannel().supportedOptions();
    }
}
