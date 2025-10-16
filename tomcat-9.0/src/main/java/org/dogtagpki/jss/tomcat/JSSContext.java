package org.dogtagpki.jss.tomcat;

import java.security.KeyManagementException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.mozilla.jss.JSSProvider;
import org.mozilla.jss.provider.javax.crypto.JSSKeyManager;
import org.mozilla.jss.provider.javax.crypto.JSSTrustManager;
import org.mozilla.jss.ssl.javax.JSSEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
* Implements the {@link SSLContext} interface from Tomcat for creating SSL connections.
* 
* This class is a wrapper around the Mozilla-JSS implementation of JSSE, which
* provides additional functionality not available in the SunJSSE implementation.
*
* @see org.apache.tomcat.util.net.SSLContext
* @see org.mozilla.jss.ssl.KeyManagerFactory#getInstance(String algorithm, String provider)
* @see org.mozilla.jss.ssl.TrustManagerFactory#getInstance(String algorithm, String provider)
*/
public class JSSContext implements org.apache.tomcat.util.net.SSLContext {
    public static Logger logger = LoggerFactory.getLogger(JSSContext.class);

    private javax.net.ssl.SSLContext ctx;
    private List<String> aliases;

    private JSSKeyManager jkm;
    private JSSTrustManager jtm;

    /**
     * Create the cContext for SSL connections.
     */
    public JSSContext() {
        /* These KeyManagers and TrustManagers aren't used with the SSLEngine;
         * they're only used to implement certain function calls below. */
        try {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("NssX509", "Mozilla-JSS");
            jkm = (JSSKeyManager) kmf.getKeyManagers()[0];

            TrustManagerFactory tmf = TrustManagerFactory.getInstance("NssX509", "Mozilla-JSS");
            jtm = (JSSTrustManager) tmf.getTrustManagers()[0];
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    /**
     * Create the cContext for SSL connections.
     *
     * @param alias Certificate nickname used by the server for the connections.
     */
    public JSSContext(String alias) {
        this();
        logger.debug("JSSContext(" + alias + ")");
        aliases = new ArrayList<>();
        aliases.add(alias);
    }

    /**
     * Create the cContext for SSL connections.
     *
     * @param aliases List of certificate nicknames used by the server for the connections.
     */
    public JSSContext(List<String> aliases) {
        this();
        logger.debug("JSSContext(" + (aliases == null ? "NO aliases" : String.join(", ", aliases)) + ")");
        this.aliases = aliases;
    }

    @Override
    public void init(KeyManager[] kms, TrustManager[] tms, SecureRandom sr) throws KeyManagementException {
        logger.debug("JSSContext.init(...)");

        try {
            String provider = "SunJSSE";
            if (JSSProvider.ENABLE_JSSENGINE) {
                provider = "Mozilla-JSS";
            }

            ctx = javax.net.ssl.SSLContext.getInstance("TLS", provider);
            ctx.init(kms, tms, sr);
        } catch (Exception e) {
            throw new KeyManagementException(e.getMessage(), e);
        }
    }

    @Override
    public javax.net.ssl.SSLEngine createSSLEngine() {
        logger.debug("JSSContext.createSSLEngine()");
        javax.net.ssl.SSLEngine eng = ctx.createSSLEngine();

	TomcatJSS instance = TomcatJSS.getInstance();

        if (eng instanceof JSSEngine) {
            JSSEngine j_eng = (JSSEngine) eng;
            j_eng.setCertFromAliases(aliases);
            if(instance != null) {
                j_eng.setListeners(instance.getSocketListeners());
            }
        }

        return eng;
    }

    @Override
    public javax.net.ssl.SSLSessionContext getServerSessionContext() {
        logger.debug("JSSContext.getServerSessionContext()");
        return ctx.getServerSessionContext();
    }

    @Override
    public javax.net.ssl.SSLServerSocketFactory getServerSocketFactory() {
        logger.debug("JSSContext.getServerSocketFactory()");
        return ctx.getServerSocketFactory();
    }

    @Override
    public javax.net.ssl.SSLParameters getSupportedSSLParameters() {
        logger.debug("JSSContext.getSupportedSSLParameters()");
        return ctx.getSupportedSSLParameters();
    }

    @Override
    public java.security.cert.X509Certificate[] getCertificateChain(java.lang.String alias) {
        logger.debug("JSSContext.getCertificateChain(" + alias + ")");

        try {
            return jkm.getCertificateChain(alias);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
        logger.debug("JSSContext.getAcceptedIssuers()");

        try {
            return jtm.getAcceptedIssuers();
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public void destroy() {
        logger.debug("JSSContext.destroy()");
    }
}
