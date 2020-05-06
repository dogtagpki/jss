package org.mozilla.jss.provider.javax.net;

import java.security.*;
import java.util.ArrayList;

import javax.net.ssl.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.provider.javax.crypto.JSSKeyManager;
import org.mozilla.jss.provider.javax.crypto.JSSTrustManager;
import org.mozilla.jss.pkcs11.PK11Cert;
import org.mozilla.jss.pkcs11.PK11PrivKey;
import org.mozilla.jss.ssl.javax.JSSEngine;
import org.mozilla.jss.ssl.javax.JSSEngineReferenceImpl;
import org.mozilla.jss.ssl.javax.JSSParameters;
import org.mozilla.jss.ssl.javax.JSSServerSocketFactory;
import org.mozilla.jss.ssl.javax.JSSSocketFactory;
import org.mozilla.jss.ssl.SSLVersion;

public class JSSContextSpi extends SSLContextSpi {
    public static Logger logger = LoggerFactory.getLogger(JSSContextSpi.class);

    JSSKeyManager key_manager;
    X509TrustManager[] trust_managers;

    SSLVersion protocol_version;

    public void engineInit(KeyManager[] kms, TrustManager[] tms, SecureRandom sr) throws KeyManagementException {
        logger.debug("JSSContextSpi.engineInit(" + kms + ", " + tms + ", " + sr + ")");

        if (kms != null) {
            for (KeyManager km : kms) {
                if (km instanceof JSSKeyManager) {
                    key_manager = (JSSKeyManager) km;
                    break;
                }
            }
        }

        if (tms != null) {
            ArrayList<X509TrustManager> xtms = new ArrayList<X509TrustManager>();
            for (TrustManager tm : tms) {
                if (tm instanceof X509TrustManager) {
                    xtms.add((X509TrustManager) tm);
                }
            }

            trust_managers = xtms.toArray(new X509TrustManager[xtms.size()]);
        }
    }

    public SSLEngine engineCreateSSLEngine() {
        logger.debug("JSSContextSpi.engineCreateSSLEngine()");

        JSSEngine ret = new JSSEngineReferenceImpl();
        initializeEngine(ret);

        return ret;
    }

    public SSLEngine engineCreateSSLEngine(String host, int port) {
        logger.debug("JSSContextSpi.engineCreateSSLEngine(" + host + ", " + port + ")");

        JSSEngine ret = new JSSEngineReferenceImpl(host, port);
        initializeEngine(ret);

        return ret;
    }

    private void initializeEngine(JSSEngine eng) {
        eng.setKeyManager(key_manager);
        eng.setTrustManagers(trust_managers);

        if (protocol_version != null) {
            eng.setEnabledProtocols(protocol_version, protocol_version);
        }
    }

    public SSLSessionContext engineGetClientSessionContext() {
        logger.debug("JSSContextSpi.engineGetClientSessionContext() - not implemented");
        return null;
    }

    public SSLSessionContext engineGetServerSessionContext() {
        logger.debug("JSSContextSpi.engineGetServerSessionContext() - not implemented");
        return null;
    }

    public SSLServerSocketFactory engineGetServerSocketFactory() {
        String protocol = "TLS";
        if (protocol_version != null) {
            protocol = protocol_version.jdkAlias();
        }

        logger.debug("JSSContextSpi.engineGetServerSocketFactory() @ " + protocol);
        return new JSSServerSocketFactory(protocol, key_manager, trust_managers);
    }

    public SSLSocketFactory engineGetSocketFactory() {
        String protocol = "TLS";
        if (protocol_version != null) {
            protocol = protocol_version.jdkAlias();
        }

        logger.debug("JSSContextSpi.engineGetSocketFactory() @ " + protocol);
        return new JSSSocketFactory(protocol, key_manager, trust_managers);
    }

    public SSLParameters engineGetSupportedSSLParameters() {
        JSSParameters params = new JSSParameters();
        params.setCipherSuites(JSSEngine.queryEnabledCipherSuites());
        params.setProtocols(JSSEngine.queryEnabledProtocols());
        return params;
    }

    public class TLSv11 extends JSSContextSpi {
        public TLSv11() {
            protocol_version = SSLVersion.TLS_1_1;
        }
    }

    public class TLSv12 extends JSSContextSpi {
        public TLSv12() {
            protocol_version = SSLVersion.TLS_1_2;
        }
    }

    public class TLSv13 extends JSSContextSpi {
        public TLSv13() {
            protocol_version = SSLVersion.TLS_1_3;
        }
    }
}
