package org.mozilla.jss.ssl.javax;

import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.mozilla.jss.crypto.Policy;
import org.mozilla.jss.nss.*;
import org.mozilla.jss.pkcs11.*;
import org.mozilla.jss.provider.javax.crypto.*;
import org.mozilla.jss.ssl.*;

/**
 * JSS's SSLEngine base class for alternative implementations.
 *
 * This abstracts out many components for all JSS SSLEngine implementations,
 * such as cipher suite support, SSLSession creation, and various other
 * common functions. This allows alternative SSLEngine implementations to
 * focus on two main things: wrap/unwrap and init.
 *
 * There are the following implementations:
 *  - JSSEngineReferenceImpl - A reference implementation with extensive
 *                             logging and debugging.
 *
 * Usually a JSSEngine isn't constructed directly, but instead accessed via
 * the Provider mechanism, SSLContext. See JSSContextSpi for more information.
 */
public abstract class JSSEngine extends javax.net.ssl.SSLEngine {
    public static Logger logger = LoggerFactory.getLogger(JSSEngine.class);

    /**
     * Size of the underlying BUFFERs.
     *
     * Helps to be large enough to fit most common SSL packets during the
     * initial handshake.
     */
    protected static int BUFFER_SIZE = 1 << 12;

    /**
     * Whether or not this SSLEngine is acting as the client end of the
     * handshake.
     */
    protected boolean as_server;

    /**
     * Peer's hostname, used for certificate validation.
     *
     */
    protected String hostname;

    /**
     * Certificate alias used by the JSSEngine instance.
     */
    protected String certAlias;

    /**
     * Certificate used by this JSSEngine instance.
     *
     * Selected and inferred from the KeyManagers passed, when not passed
     * explicitly (either during construction or with a call to
     * setKeyMaterials(...)).
     */
    protected PK11Cert cert;

    /**
     * Key corresponding to the local certificate.
     */
    protected PK11PrivKey key;

    /**
     * A list of all KeyManagers available to this JSSEngine instance.
     *
     * Note: currently only a single JSSKeyManager instance is exposed,
     * and it can only handle finding a single certificate by nickname.
     * In the future, more KeyManagers should be supported.
     */
    protected X509KeyManager[] key_managers;

    /**
     * A list of all TrustManagers available to this JSSEngine instance.
     *
     * The behavior of this list depends on how which TrustManagers are
     * passed.
     */
    protected X509TrustManager[] trust_managers;

    /**
     * Whether or not we should fail to handshake if client authentication
     * is not passed by the peer and we are a server; if we are a client,
     * whether or not we offer our certificate to the server.
     *
     * See also the note for want_client_auth.
     */
    protected boolean need_client_auth;

    /**
     * Whether or not we should attempt to handshake with client
     * authentication.
     *
     * Note that under a strict reading of the SSLEngine spec, this is
     * mutually exclusive with need_client_auth: either want_client_auth
     * or need_client_auth can be true, but not both. However, both can
     * be false.
     *
     * Under NSS semantics however, we have control over two values: whether
     * we offer/request client auth, and whether we should fail to handshake
     * if we don't get client auth. This doesn't quite map onto the want/need
     * semantics, but it is what we have available.
     */
    protected boolean want_client_auth;

    /**
     * What the official SSLEngineResult handshake status is, at the present
     * time.
     *
     * Note that while we store the current handshake state in JSSEngine, we
     * don't implement getHandshakeStatus(...), as different JSSEngine
     * implementations could have different implementations for that method.
     */
    protected SSLEngineResult.HandshakeStatus handshake_state = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;

    /**
     * A list of all ciphers enabled by this SSLEngine.
     *
     * This list is restricted to a list of ciphers that are supported and
     * approved by local policy.
     */
    protected SSLCipher[] enabled_ciphers;

    /**
     * The minimum TLS protocol version we should attempt to handshake.
     *
     * This version is tempered by local policy, when applicable.
     */
    protected SSLVersion min_protocol;

    /**
     * The maximum TLS protocol version we should attempt to handshake.
     *
     * This version is tempered by local policy, when applicable.
     */
    protected SSLVersion max_protocol;

    /**
     * A JSSSession extends the SSLSession, providing useful information not
     * otherwise contained in the SSLSession, but exposed by NSS.
     */
    protected JSSSession session;

    /**
     * Internal SSLFDProxy instance; useful for JSSSession support and any
     * custom extensions the developer wishes to support.
     */
    protected SSLFDProxy ssl_fd;

    /**
     * Whether or not the outbound portion of this connection is closed.
     */
    protected boolean is_outbound_closed;

    /**
     * Whether or not the inbound portion of this connection is closed.
     */
    protected boolean is_inbound_closed;

    /**
     * Set of configuration options to enable via SSL_OptionSet(...).
     */
    protected HashMap<Integer, Integer> config;

    /**
     * Set of cached server sockets based on the PK11Cert they were
     * initialized with.
     */
    protected static HashMap<PK11Cert, SSLFDProxy> serverTemplates = new HashMap<PK11Cert, SSLFDProxy>();

    /**
     * Whether or not the session cache has been initialized already.
     *
     * A session cache must always be created in order to utilize a
     * server-side JSSEngine. However, NSS isn't threadsafe when creating
     * such a cache, so synchronize it within JSSEngine.
     */
    private final static AtomicBoolean sessionCacheInitialized = new AtomicBoolean();

    /**
     * Constructor for a JSSEngine, providing no hints for an internal
     * session reuse strategy and no key.
     *
     * This should always be called from an implementation's corresponding
     * constructor.
     */
    public JSSEngine() {
        super();

        session = new JSSSession(this, BUFFER_SIZE);
        config = getDefaultConfiguration();
    }

    /**
     * Constructor for a JSSEngine, providing hints for an internal session
     * reuse strategy (the peer's hostname and port), but no local cert or key.
     *
     * This should always be called from an implementation's corresponding
     * constructor.
     */
    public JSSEngine(String peerHost, int peerPort) {
        super(peerHost, peerPort);

        session = new JSSSession(this, BUFFER_SIZE);
        session.setPeerHost(peerHost);
        session.setPeerPort(peerPort);
        config = getDefaultConfiguration();
    }

    /**
     * Constructor for a JSSEngine, providing hints for an internal session
     * reuse strategy (the peer's hostname and port), along with a chosen
     * certificate and key to use.
     *
     * This should always be called from an implementation's corresponding
     * constructor.
     */
    public JSSEngine(String peerHost, int peerPort,
                     org.mozilla.jss.crypto.X509Certificate localCert,
                     org.mozilla.jss.crypto.PrivateKey localKey) {
        super(peerHost, peerPort);

        cert = (PK11Cert) localCert;
        key = (PK11PrivKey) localKey;

        session = new JSSSession(this, BUFFER_SIZE);
        session.setPeerHost(peerHost);
        session.setPeerPort(peerPort);
        config = getDefaultConfiguration();
    }

    /**
     * Gets the error text from the NSPR layer
     */
    protected static String errorText(int error) {
        // Convert the given error into a pretty string representation with
        // as much information as is currently available.

        String error_name = PR.ErrorToName(error);
        String error_text = PR.GetErrorText();

        if (error == 0) {
            return "NO ERROR";
        } else if (error_name.isEmpty()) {
            return "UNKNOWN (" + error + ")";
        } else if (error_text.isEmpty()) {
            return error_name + " (" + error + ")";
        } else {
            return error_name + " (" + error + "): " + error_text;
        }
    }

    /**
     * Safely initializes the session cache if not already initialized.
     */
    public static void initializeSessionCache(int maxCacheEntries,
        long timeout, String directory) throws SSLException
    {
        if (sessionCacheInitialized.compareAndSet(false, true)) {
            if (SSL.ConfigServerSessionIDCache(maxCacheEntries, timeout, timeout, directory) == SSL.SECFailure) {
                String msg = "Unable to configure server session cache: ";
                msg += errorText(PR.GetError());
                throw new SSLException(msg);
            }
        }
    }

    /**
     * Get the internal SSLFDProxy object; this should be preferred to
     * directly accessing ssl_fd.
     *
     * Note that ssl_fd can be null at various times during SSLEngine
     * initialization and destruction. This method should be used with
     * caution as callers can risk damaging the SSLEngine and making it
     * unusable or crash.
     */
    public SSLFDProxy getSSLFDProxy() {
        return ssl_fd;
    }

    /**
     * Get the configuration from the current JSSEngine object as a
     * JSSParameters object.
     *
     * This populates the following values, when set:
     *  - cipher suites
     *  - protocols
     *  - need/want client auth
     *  - certificate alias
     *  - peer's hostname
     *  - ALPN protocols
     */
    public JSSParameters getSSLParameters() {
        JSSParameters ret = new JSSParameters();

        ret.setCipherSuites(getEnabledCipherSuites());
        ret.setProtocols(getEnabledProtocols());
        if (getNeedClientAuth()) {
            ret.setNeedClientAuth(true);
        } else if (getWantClientAuth()) {
            ret.setWantClientAuth(true);
        }

        ret.setAlias(certAlias);
        ret.setHostname(hostname);

        return ret;
    }

    /**
     * Set the configuration from the given SSLParameters object onto this
     * JSSEngine.
     *
     * Aligning with the parent implementation, this calls:
     *  - setEnabledCipherSuites when getCipherSuites is non-null,
     *  - setEnabledProtocols when getProtocols is non-null, and
     *  - setWantClientAuth and setNeedClientAuth.
     *
     * This doesn't yet understand from the parent implementation, the
     * following calls:
     * - getServerNames for the local server certificate selection, and
     * - getSNIMatchers for configuring SNI selection criteria
     *
     * Unlike the parent, this also understands:
     *  - setCertFromAlias when getAlias is non-null,
     * - setHostname when getHostname is non-null.
     *
     * Note: this implementation overrides the one in SSLEngine so that we
     * create a JSSParameters object from the passed SSLParameters (if it is
     * not already an instance of JSSParameters), simplifying the other
     * function calls and reducing duplicate parsing.
     */
    public void setSSLParameters(SSLParameters params) {
        JSSParameters parsed;

        // Try to cast the passed parameter into a JSSParameters. This has
        // additional fields we usually need for construction of a NSS-backed
        // SSLEngine. Otherwise, parse the values into JSS-specific fields.
        // If we didn't create the JSSParameters here, both calls
        // (setEnabledCipherSuites, setEnabledProtocols) would construct their
        // own JSSParameters.
        if (params instanceof JSSParameters) {
            parsed = (JSSParameters) params;
        } else {
            parsed = new JSSParameters(params);
        }

        // Per semantics from parent class.
        if (parsed.getSSLCiphers() != null) {
            setEnabledCipherSuites(parsed.getSSLCiphers());
        }

        // Per semantics from parent class.
        if (parsed.getSSLVersionRange() != null) {
            setEnabledProtocols(parsed.getSSLVersionRange());
        }

        // Differing from the semantics of the parent class, we always set
        // these from the values in the parsed JSSParameters. This is because
        // NSS has a different set of expectations.
        setWantClientAuth(parsed.getWantClientAuth());
        setNeedClientAuth(parsed.getNeedClientAuth());

        // In the event we haven't explicitly set cert and key, try and infer
        // them from the alias specified... We assume that when the SSLEngine
        // has a certificate already, we want to use them, even if parsed has
        // a null certificate.
        if (parsed.getAlias() != null && key_managers != null && key_managers.length > 0 && cert == null && key == null) {
            setCertFromAlias(parsed.getAlias());
        }

        // When we have a value for the peer hostname, we should try and use
        // it.
        if (parsed.getHostname() != null) {
            setHostname(parsed.getHostname());
        }
    }

    /**
     * Set the hostname used to validate the peer's certificate.
     *
     * This is usually passed to NSS via a call to NSS's ill-named
     * SSL_SetURL(...), which really takes a hostname.
     *
     * Note: if this isn't called (and no peerHost was specified via a
     * constructor), NSS will accept any host name provided by the server!
     * Only useful for validating the server certificate; not used when
     * validating the peer's certificate.
     */
    public void setHostname(String name) {
        // Note, this is the only way to set the hostname used for validation.
        //
        // In the event setHostname is never explicitly called, we should try
        // and fall back to the value passed in the constructor.
        hostname = name;
    }

    /**
     * Choose a certificate to give to the peer from the specified alias,
     * assuming KeyManagers have already been specified and at least one is
     * a JSSKeyManager.
     *
     * When alias is null, this clears all previous certs and keys.
     *
     * If no KeyManagers have been specified, raises an
     * IllegalArgumentException stating as much.
     *
     */
    public void setCertFromAlias(String alias) throws IllegalArgumentException {
        if (alias == null) {
            // Per calling, semantics, get rid of any existing cert/key we
            // might have.
            certAlias = null;
            cert = null;
            key = null;
            return;
        }

        certAlias = alias;

        if (key_managers == null || key_managers.length == 0) {
            String msg = "Missing or null KeyManagers; refusing to search ";
            msg += "for cert";
            throw new IllegalArgumentException(msg);
        }

        for (X509KeyManager key_manager : key_managers) {
            if (key_manager == null) {
                // Skip this key_manager. This case could occur when
                // setKeyManagers(...) is passed an array containing the value
                // null, but otherwise shouldn't happen.
                continue;
            }

            if (!(key_manager instanceof JSSKeyManager)) {
                // We're explicitly looking for a JSSKeyManager; skip this if
                // it doesn't match.
                continue;
            }

            JSSKeyManager jkm = (JSSKeyManager) key_manager;

            // While the return type of CryptoManager.findCertByNickname is
            // technically org.mozilla.jss.crypto.X509Certificate, in practice
            // they are always PK11Cert instances. We're going to need an
            // instance of PK11Cert anyways, in order to correctly pass it to
            // the native layer.
            cert = (PK11Cert) jkm.getCertificate(alias);
            key = (PK11PrivKey) jkm.getPrivateKey(alias);

            if (cert != null && key != null) {
                // Found a cert and key matching our alias; exit.
                break;
            }
        }

        if (cert == null && key == null) {
            String msg = "JSSEngine.setCertFromAlias: Unable to find ";
            msg += "certificate and key for specified alias!";
            throw new IllegalArgumentException(msg);
        }
    }

    /**
     * Sets the list of enabled cipher suites from a list of JCA-approved
     * String names.
     *
     * Note: this method is slower than creating a JSSParameters configuration
     * object and calling setSSLParameters(...) with it. This call must
     * construct its own JSSParameters instance internally and translate
     * between JCA String names and SSLCipher instances.
     */
    public void setEnabledCipherSuites(String[] suites) throws IllegalArgumentException {
        JSSParameters parser = new JSSParameters();
        parser.setCipherSuites(suites);

        setEnabledCipherSuites(parser.getSSLCiphers());
    }

    /**
     * Sets the list of enabled cipher suites from a a list of SSLCipher enum
     * instances.
     */
    public void setEnabledCipherSuites(SSLCipher[] suites) throws IllegalArgumentException {
        if (ssl_fd != null) {
            String msg = "Unable to process setEnabledCipherSuites(...) ";
            msg += "after handshake has started!";
            throw new IllegalArgumentException(msg);
        }

        if (suites == null || suites.length == 0) {
            enabled_ciphers = null;
            logger.warn("JSSEngine.setEnabledCipherSuites(...) given a null list of cipher suites.");
            return;
        }

        ArrayList<SSLCipher> supportedCiphers = new ArrayList<SSLCipher>();
        for (SSLCipher suite : suites) {
            if (suite.isSupported()) {
                supportedCiphers.add(suite);
            }
        }

        if (supportedCiphers.size() == 0) {
            enabled_ciphers = null;
            logger.warn("JSSEngine.setEnabledCipherSuites(...) given a list of cipher suites where none were supported or approved.");
            return;
        }

        enabled_ciphers = supportedCiphers.toArray(new SSLCipher[supportedCiphers.size()]);
    }

    /**
     * Queries the list of cipher suites enabled by default, if a
     * corresponding setEnabledCIpherSuites call hasn't yet been made.
     */
    public static SSLCipher[] queryEnabledCipherSuites() {
        logger.debug("JSSEngine: queryEnabledCipherSuites()");
        ArrayList<SSLCipher> enabledCiphers = new ArrayList<SSLCipher>();

        for (SSLCipher cipher : SSLCipher.values()) {
            try {
                if (SSL.CipherPrefGetDefault(cipher.getID()) && cipher.isSupported()) {
                    logger.debug("Enabled: " + cipher.name() + " (" + cipher.getID() + ")");
                    enabledCiphers.add(cipher);
                }
            } catch (Exception e) {
                // Do nothing -- this shouldn't happen as SSLCipher should be
                // synced with NSS. However, we'll just log this exception as
                // a warning. At worst we fail to report that a cipher suite is
                // enabled.
                logger.warn("Unable to get the value of cipher: " + cipher.name() + " (" + cipher.getID() + "): " + e.getMessage());
            }
        }

        return enabledCiphers.toArray(new SSLCipher[0]);
    }

    /**
     * Lists cipher suites currently enabled on this JSSEngine instance.
     */
    public String[] getEnabledCipherSuites() {
        logger.debug("JSSEngine: getEnabledCipherSuites()");

        // This only happens in the event that setEnabledCipherSuites(...)
        // isn't called. In which case, we'll need to explicitly query the
        // list of default cipher suites.
        if (enabled_ciphers == null) {
            enabled_ciphers = queryEnabledCipherSuites();
        }

        // Use JSSParameters to do the heavy lifting of converting our list
        // of cipher suites to an array of Strings.
        JSSParameters parser = new JSSParameters();
        parser.setCipherSuites(enabled_ciphers);
        return parser.getCipherSuites();
    }

    /**
     * Lists all cipher suites supported by JSS/NSS.
     *
     * Note that this list isn't just all values in SSLCipher: it is only
     * those which are supported and allowed by local policy.
     */
    public String[] getSupportedCipherSuites() {
        logger.debug("JSSEngine: getSupportedCipherSuites()");
        ArrayList<String> result = new ArrayList<String>();

        for (SSLCipher c : SSLCipher.values()) {
            if (c.isSupported()) {
                logger.debug("JSSEngine: getSupportedCipherSuites() - Supported: " + c);
                result.add(c.name());
            }
        }

        return result.toArray(new String[result.size()]);
    }

    /**
     * Set the range of SSL protocols enabled by this SSLEngine instance, from
     * a list of JCA-standardized protocol String names.
     *
     * Note that this enables all protocols in the range of min(protocols) to
     * max(protocols), inclusive due to the underlying call to NSS's
     * SSL_VersionRangeSet(...).
     *
     * It is also recommend to construct your own JSSParameters object first
     * and pass it to setSSLParameters(...), rather than calling this method
     * directly.
     */
    public void setEnabledProtocols(String[] protocols) throws IllegalArgumentException {
        logger.debug("JSSEngine: setEnabledProtocols(");
        for (String protocol : protocols) {
            logger.debug("\t" + protocol + ",");
        }
        logger.debug(")");

        JSSParameters parser = new JSSParameters();
        parser.setProtocols(protocols);

        SSLVersionRange vrange = parser.getSSLVersionRange();
        setEnabledProtocols(vrange);
    }

    /**
     * Sets the range of enabled SSL Protocols from a minimum and maximum
     * SSLVersion value.
     */
    public void setEnabledProtocols(SSLVersion min, SSLVersion max) throws IllegalArgumentException {
        logger.debug("JSSEngine: setEnabledProtocols()");
        if ((min_protocol == null && max_protocol != null) || (min_protocol != null && max_protocol == null)) {
            throw new IllegalArgumentException("Expected min and max to either both be null or both be not-null; not mixed: (" + min + ", " + max + ")");
        }

        if (max == null && min == null) {
            min_protocol = null;
            max_protocol = null;
            return;
        }

        setEnabledProtocols(new SSLVersionRange(min, max));
    }

    /**
     * Sets the range of enabled SSL Protocols from a SSLVersionRange object.
     */
    public void setEnabledProtocols(SSLVersionRange vrange) {
        logger.debug("JSSEngine: setEnabledProtocols()");
        if (vrange == null) {
            min_protocol = null;
            max_protocol = null;
            return;
        }

        if (ssl_fd != null) {
            String msg = "Unable to process setEnabledProtocols(...) after ";
            msg += "handshake has started!";
            throw new IllegalArgumentException(msg);
        }

        SSLVersionRange bounded = vrange.boundBy(Policy.TLS_VERSION_RANGE);
        min_protocol = bounded.getMinVersion();
        max_protocol = bounded.getMaxVersion();
    }

    /**
     * Queries the list of protocols enabled by default.
     *
     * Only used when setEnabledProtocols(...) hasn't yet been called.
     */
    public static SSLVersionRange queryEnabledProtocols() {
        logger.debug("JSSEngine: queryEnabledProtocols()");

        SSLVersionRange vrange;
        try {
            vrange = SSL.VersionRangeGetDefault();
        } catch (Exception e) {
            // This shouldn't happen unless the PRFDProxy is null.
            throw new RuntimeException("JSSEngine.queryEnabledProtocols() Unexpected failure: " + e.getMessage(), e);
        }

        if (vrange == null) {
            // Again; this shouldn't happen as the vrange should always
            // be created by VersionRangeGet(...).
            throw new RuntimeException("JSSEngine.queryEnabledProtocols() - null protocol range");
        }

        return vrange.boundBy(Policy.TLS_VERSION_RANGE);
    }

    /**
     * Gets the list of enabled SSL protocol versions on this particular
     * JSSEngine instance, as a list of JCA-standardized strings.
     */
    public String[] getEnabledProtocols() {
        logger.debug("JSSEngine: getEnabledProtocols()");

        if (min_protocol == null || max_protocol == null) {
            SSLVersionRange vrange = queryEnabledProtocols();
            min_protocol = vrange.getMinVersion();
            max_protocol = vrange.getMaxVersion();
        }

        // Use JSSParameters to do the heavy lifting of converting the
        // SSLVersionRange to a list of JDK-conforming Strings.
        JSSParameters parser = new JSSParameters();
        parser.setProtocols(min_protocol, max_protocol);
        return parser.getProtocols();
    }

    /**
     * Gets the list of SSL protocols supported, as a list of JCA-standardized
     * strings.
     */
    public String[] getSupportedProtocols() {
        logger.debug("JSSEngine: getSupportedProtocols()");
        ArrayList<String> result = new ArrayList<String>();

        for (SSLVersion v : Policy.TLS_VERSION_RANGE.getAllInRange()) {
            logger.debug("JSSEngine: getSupportedProtocol - Supported: " + v);
            result.add(v.jdkAlias());
        }

        return result.toArray(new String[result.size()]);
    }

    /**
     * Set public and protected key material; useful when doing client auth or
     * if this wasn't provided to the constructor.
     *
     * Can also be used to remove key material; however note that both
     * arguments must match: either both certificate and key are null or
     * both are not-null.
     */
    public void setKeyMaterials(PK11Cert our_cert, PK11PrivKey our_key) throws IllegalArgumentException {
        logger.debug("JSSEngine: setKeyMaterials()");

        if ((our_cert == null && our_key != null) || (our_cert != null && our_key == null)) {
            throw new IllegalArgumentException("JSSEngine.setKeyMaterials(): Either both cert and key must be null or both must be not-null");
        }

        cert = our_cert;
        key = our_key;
    }

    /**
     * Set the internal KeyManager, when present, replacing all previous
     * KeyManagers.
     *
     * It is suggested that at least one key manager be a JSSKeyManager
     * instance if a key and certificate must be provided for this end of
     * the connection.
     */
    public void setKeyManager(X509KeyManager km) {
        if (km == null) {
            logger.debug("JSSEngine: setKeyManager(null)");
            return;
        }

        logger.debug("JSSEngine: setKeyManager(" + km.getClass().getName() + ")");
        key_managers = new X509KeyManager[] { km };
    }

    /**
     * Set the internal list of KeyManagers.
     *
     * It is suggested that at least one key manager be a JSSKeyManager
     * instance if a key and certificate must be provided for this end of
     * the connection.
     */
    public void setKeyManagers(X509KeyManager[] xkms) {
        if (xkms == null) {
            logger.debug("JSSEngine: setKeyManagers([null])");
            return;
        }

        logger.debug("JSSEngine: setKeyManagers(");
        for (X509KeyManager km : xkms) {
           logger.debug(" - " + km.getClass().getName());
        }
        logger.debug(")");

        key_managers = xkms;
    }

    /**
     * Set the internal TrustManager, when present, replacing all previous
     * TrustManagers.
     */
    public void setTrustManager(JSSTrustManager tm) {
        if (tm == null) {
            logger.debug("JSSEngine: setTrustManager(null)");
            return;
        }

        logger.debug("JSSEngine: setTrustManager(" + tm.getClass().getName() + ")");
        trust_managers = new X509TrustManager[] { tm };
    }

    /**
     * Set the internal list of TrustManagers.
     */
    public void setTrustManagers(X509TrustManager[] xtms) {
        if (xtms == null) {
            logger.debug("JSSEngine: setKeyManagers([null])");
            return;
        }

        logger.debug("JSSEngine: setTrustManagers(");
        for (X509TrustManager tm : xtms) {
           logger.debug(" - " + tm.getClass().getName());
        }
        logger.debug(")");

        trust_managers = xtms;
    }

    /**
     * Gets the JSSSession object which reflects the status of this
     * JSS Engine's session.
     */
    public JSSSession getSession() {
        logger.debug("JSSEngine: getSession()");
        return session;
    }

    /**
     * Whether or not to enable this SSLEngine instance to create new
     * sessions.
     *
     * The default value is true. When passed the value false, this will
     * throw a RuntimeException, stating that all JSS Engines do not support
     * restricting to only resuming existing sessions.
     */
    public void setEnableSessionCreation(boolean flag) {
        logger.debug("JSSEngine: setEnableSessionCreation(" + flag + ") - not implemented");
        if (!flag) {
            String msg = "JSSEngine does not support restricting to only resuming existing sessions.";
            throw new RuntimeException(msg);
        }
    }

    /**
     * Whether or not new sessions can be created by this SSLEngine instance.
     *
     * This always returns true.
     */
    public boolean getEnableSessionCreation() {
        logger.debug("JSSEngine: getEnableSessionCreation() - not implemented");
        return true;
    }

    /**
     * Set whether or not to handshake as a client.
     */
    public void setUseClientMode(boolean mode) throws IllegalArgumentException {
        logger.debug("JSSEngine.setUseClientMode(" + mode + ")");
        if (ssl_fd != null) {
            String msg = "Unable to process setUseClientMode(" + mode + ") ";
            msg += "after handshake has started!";
            throw new IllegalArgumentException(msg);
        }

        as_server = !mode;
    }

    /**
     * Set whether or not client authentication is required for the TLS
     * handshake to succeed.
     */
    public void setNeedClientAuth(boolean need) {
        logger.debug("JSSEngine.setNeedClientAuth(" + need + ")");
        need_client_auth = need;

        reconfigureClientAuth();
    }

    /**
     * Set whether or not we should attempt client authentication.
     */
    public void setWantClientAuth(boolean want) {
        logger.debug("JSSEngine.setWantClientAuth(" + want + ")");
        want_client_auth = want;

        reconfigureClientAuth();
    }

    /**
     * Implementation-specific handler to handle reconfiguration of client
     * authentication after the handshake has completed.
     *
     * Note that this always gets called, regardless of if the handshake has
     * started; it is up to the implementation to handle this appropriately.
     */
    protected abstract void reconfigureClientAuth();

    /**
     * Query whether this JSSEngine is a client (true) or a server (false).
     */
    public boolean getUseClientMode() {
        return !as_server;
    }

    /**
     * Query whether or not we must have client authentication for the TLS
     * handshake to succeed.
     */
    public boolean getNeedClientAuth() {
        return need_client_auth;
    }

    /**
     * Query whether or not we request client authentication.
     */
    public boolean getWantClientAuth() {
        return want_client_auth;
    }

    /**
     * Query whether or not the inbound side of this connection is closed.
     */
    public boolean isInboundDone() {
        logger.debug("JSSEngine.isInboundDone()? " + is_inbound_closed);
        return is_inbound_closed;
    }

    /**
     * Query whether or not the outbound side of this connection is closed.
     */
    public boolean isOutboundDone() {
        logger.debug("JSSEngine.isOutboundDone()? " + is_outbound_closed);
        return is_outbound_closed;
    }

    /**
     * Gets the current security status of this JSSEngine instance.
     *
     * This is abstract to allow implementations to implement this (and step
     * their handshake mechanism) as they wish.
     */
    public abstract SecurityStatusResult getStatus();

    /**
     * Gets the default configuration.
     */
    public HashMap<Integer, Integer> getDefaultConfiguration() {
        HashMap<Integer, Integer> result = new HashMap<Integer, Integer>();

        // JSS (and NSS) generally supports post-handshake authentication, but
        // we might not always have key material up front. Set the extension
        // anyways, to give the JSSEngine the chance to negotiate it in the
        // future.
        result.put(SSL.ENABLE_POST_HANDSHAKE_AUTH, 1);

        // Allow (and enable) only secure renegotiation. Only relevant for
        // TLS < 1.3.
        result.put(SSL.ENABLE_RENEGOTIATION, SSL.RENEGOTIATE_REQUIRES_XTN);
        result.put(SSL.REQUIRE_SAFE_NEGOTIATION, 1);
        return result;
    }

    /**
     * Updates the configuration with the given value.
     */
    public void addConfiguration(int key, int value) {
        config.put(key, value);
    }

    /**
     * Removes the given key from the configuration.
     */
    public void removeConfiguration(int key) {
        config.remove(key);
    }

    /**
     * Sets the configuration, replacing all current values.
     */
    public void setConfiguration(HashMap<Integer, Integer> config) {
        this.config = config;
    }

    /**
     * Returns the templated server certificate, if one exists.
     */
    protected static SSLFDProxy getServerTemplate(PK11Cert cert, PK11PrivKey key) {
        if (cert == null || key == null) {
            return null;
        }

        SSLFDProxy fd = serverTemplates.get(cert);
        if (fd == null) {
            PRFDProxy base = PR.NewTCPSocket();
            fd = SSL.ImportFD(null, base);
            if (SSL.ConfigServerCert(fd, cert, key) != SSL.SECSuccess) {
                String msg = "Unable to configure certificate and key on ";
                msg += "model SSL PRFileDesc proxy: ";
                msg += errorText(PR.GetError());
                throw new RuntimeException(msg);
            }

            serverTemplates.put(cert, fd);
        }

        return fd;
    }

    /**
     * Calls cleanup only if both inbound and outbound data streams are
     * closed.
     *
     * This prevents accidental cleanup in the case of a partially open
     * connection.
     */
    public abstract void tryCleanup();

    /**
     * Performs cleanup of internal data, closing both inbound and outbound
     * data streams if still open.
     */
    public abstract void cleanup();
}
