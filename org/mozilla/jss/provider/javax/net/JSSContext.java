package org.mozilla.jss.provider.javax.net;

import java.security.*;

import javax.net.ssl.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.provider.javax.crypto.JSSKeyManager;
import org.mozilla.jss.provider.javax.crypto.JSSTrustManager;
import org.mozilla.jss.pkcs11.PK11Cert;
import org.mozilla.jss.pkcs11.PK11PrivKey;
import org.mozilla.jss.ssl.javax.JSSEngine;

public class JSSContext extends SSLContextSpi {
    public static Logger logger = LoggerFactory.getLogger(JSSContext.class);

    JSSKeyManager key_manager = null;
    JSSTrustManager trust_manager = null;

    public void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) throws KeyManagementException {
        logger.debug("JSSContext: engineInit(" + km + ", " + tm + ", " + sr + ")");

        if (km != null) {
            for (KeyManager k : km) {
                if (k instanceof JSSKeyManager) {
                    key_manager = (JSSKeyManager) k;
                    break;
                }
            }
        }

        if (tm != null) {
            for (TrustManager t : tm) {
                if (t instanceof JSSTrustManager) {
                    trust_manager = (JSSTrustManager) t;
                    break;
                }
            }
        }
    }

    public SSLEngine engineCreateSSLEngine() {
        logger.debug("JSSContext: engineCreateSSLEngine()");

        JSSEngine ret = new JSSEngine();
        initializeEngine(ret);

        return ret;
    }

    public SSLEngine engineCreateSSLEngine(String host, int port) {
        logger.debug("JSSContext: engineCreateSSLEngine(" + host + ", " + port + ")");

        JSSEngine ret = new JSSEngine(host, port);
        initializeEngine(ret);

        return ret;
    }

    private void initializeEngine(JSSEngine eng) {
        eng.setKeyManager(key_manager);
        eng.setTrustManager(trust_manager);
    }

    public SSLSessionContext engineGetClientSessionContext() {
        logger.debug("JSSContext: engineGetClientSessionContext() - not implemented");
        return null;
    }

    public SSLSessionContext engineGetServerSessionContext() {
        logger.debug("JSSContext: engineGetServerSessionContext() - not implemented");
        return null;
    }

    public SSLServerSocketFactory engineGetServerSocketFactory() {
        logger.debug("JSSContext: engineGetServerSocketFactory() - not implemented");
        return null;
    }

    public SSLSocketFactory engineGetSocketFactory() {
        logger.debug("JSSContext: engineGetSocketFactory() - not implemented");
        return null;
    }
}
