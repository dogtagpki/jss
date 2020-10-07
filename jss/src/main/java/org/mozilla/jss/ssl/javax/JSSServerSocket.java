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
 * SSL-enabled server socket following the javax.net.ssl.SSLServerSocket
 * interface.
 *
 * Most users will want to use the JSSServerSocketFactory provided by the Java
 * Provider interface instead of using this class directly.
 *
 * This SSLSocket implementation is a wrapped implementation. In particular, we
 * need to consume an existing ServerSocket (via the consumeSocket(...) call)
 * which we actually use for the accept() call. When called from a socket
 * factory, this additional socket will be automatically created for the
 * caller.
 *
 * All JSSServerSocket instances have a underlying ServerSocketChannel, of type
 * JSSServerSocketChannel. Notably lacking from javax.net.ssl is a
 * javax.net.ssl.SSLServerSocketChannel interface, so JSSSocketChannel includes
 * no additional SSL-specific options. This purely exists to facilitate
 * creating JSSSocket instances.
 *
 * In order to interoperate with JSSEngine, many of the adjacent methods have
 * been included in this class as well. This results in any accepted sockets
 * cloning its configuration.
 *
 * To construct a (useful) new instance, the following calls must be made:
 *
 * - new JSSServerSocket();
 * - consumeSocket(inst);
 * - initSSLEngine(...);
 * - setKeyManagers(...);
 * - setTrustManagers(...);
 *
 * Optionally, setSSLContext(...) could be called to provide the SSLContext
 * from which the SSLEngine should be constructed. This should be called prior
 * to initSSLEngine(...) being called.
 */
public class JSSServerSocket extends SSLServerSocket {
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
     * The socket this JSSServerSocket was created over; accept() operations
     * go through this socket and all information exposed via ServerSocket
     * members go through here.
     */
    private ServerSocket parent;

    /**
     * Underlying SocketChannel for this socket; always exists.
     */
    private JSSServerSocketChannel channel;

    /**
     * Start building a new JSSServerSocket.
     *
     * We specifically avoid creating any other constructors as we wish to
     * consume an existing socket rather than creating a new one.
     */
    public JSSServerSocket() throws IOException {}

    /**
     * Consume a parent socket, utilizing it for all accept operations.
     *
     * This JSSServerSocket instance will inherit all information about the
     * connection from this underlying socket. When utilized in a
     * JSSServerSocket, callers should refrain from interacting with the
     * underlying socket unless selective protocol upgrade should occur. In
     * that case, it may be more appropriate to use the JSSSocketFactory
     * method that creates server JSSSocket instances.
     */
    public void consumeSocket(ServerSocket parent) {
        this.parent = parent;
    }

    /**
     * Get the SSLContext if one exists or create a new instance.
     *
     * This is used by initSSLEngine(..) to create the underlying SSLEngine.
     */
    protected SSLContext getSSLContext() throws IOException {
        if (jssContext == null) {
            try {
                jssContext = SSLContext.getInstance(engineProviderProtocol, engineProvider);
            } catch (Exception e) {
                throw new IOException("Unable to create JSSSocket prior to Mozilla-JSS initialization! " + e.getMessage(), e);
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
     * Initialize the underlying ServerSocketChannel.
     */
    private void init() throws IOException {
        if (engine == null) {
            initEngine();
        }

        ServerSocketChannel parentChannel = parent.getChannel();
        if (parentChannel == null) {
            channel = new JSSServerSocketChannel(this, parent, engine);
        } else {
            channel = new JSSServerSocketChannel(this, parentChannel, engine);
        }
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
     * Get the underlying ServerSocketChannel for this Socket.
     *
     * @see java.net.ServerSocket#getChannel()
     */
    public JSSServerSocketChannel getChannel() {
        if (parent.getChannel() == null) {
            return null;
        }

        return getInternalChannel();
    }

    /**
     * Get the internal ServerSocketChannel for this Socket.
     */
    protected JSSServerSocketChannel getInternalChannel() {
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
     * Helper to upgrade a Socket into a JSSSocket.
     *
     * Called from accept in JSSServerSocket and JSSServerSocketChannel.
     */
    protected JSSSocket acceptSocket(Socket child) throws IOException {
        JSSSocket result = new JSSSocket();
        result.consumeSocket(child);
        result.setSSLContext(getSSLContext());
        result.initEngine();

        result.setKeyManagers(engine.key_managers);
        result.setTrustManagers(engine.trust_managers);

        JSSParameters params = getSSLParameters();
        result.setSSLParameters(params);

        return result;
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

    /* == stubs over SSLServerSocket == */

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

    /* == stubs over ServerSocket == */

    @Override
    public JSSSocket accept() throws IOException {
        Socket child = parent.accept();
        return acceptSocket(child);
    }

    @Override
    public void bind(SocketAddress endpoint) throws IOException {
        parent.bind(endpoint);
    }

    @Override
    public void bind(SocketAddress endpoint, int backlog) throws IOException {
        parent.bind(endpoint, backlog);
    }

    @Override
    public void close() throws IOException {
        getInternalChannel().close();
        engine = null;
    }

    @Override
    public InetAddress getInetAddress() {
        return parent.getInetAddress();
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
    public int getSoTimeout() throws IOException {
        return parent.getSoTimeout();
    }

    @Override
    public void setSoTimeout(int timeout) throws SocketException {
        parent.setSoTimeout(timeout);
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
    public int getReceiveBufferSize() throws SocketException {
        return parent.getReceiveBufferSize();
    }

    @Override
    public void setReceiveBufferSize(int size) throws SocketException {
        parent.setReceiveBufferSize(size);
    }

    @Override
    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
        parent.setPerformancePreferences(connectionTime, latency, bandwidth);
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
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("JSSServerSocket with ");
        builder.append(engine);
        builder.append(" over ");
        builder.append(parent);
        return builder.toString();
    }

    /* == stubs for Java 9 Socket == */

    public <T> ServerSocket setOption(SocketOption<T> name, T value) throws IOException {
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
