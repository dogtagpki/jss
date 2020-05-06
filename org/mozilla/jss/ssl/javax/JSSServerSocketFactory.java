package org.mozilla.jss.ssl.javax;

import java.io.*;
import java.net.*;
import java.security.*;

import javax.net.ssl.*;

import org.mozilla.jss.provider.javax.crypto.JSSKeyManager;
import org.mozilla.jss.ssl.SSLCipher;

public class JSSServerSocketFactory extends SSLServerSocketFactory {
    private SSLContext ctx;
    private JSSKeyManager key_manager;
    private X509TrustManager[] trust_managers;

    public JSSServerSocketFactory(String protocol, JSSKeyManager km, X509TrustManager[] tms) {
        try {
            ctx = SSLContext.getInstance(protocol, "Mozilla-JSS");
            ctx.init(new JSSKeyManager[]{ km }, tms, null);
        } catch (Exception e) {
            throw new RuntimeException("Unexpected error recreating SSLContext instance: " + e.getMessage(), e);
        }

        key_manager = km;
        trust_managers = tms;
    }

    public String[] getDefaultCipherSuites() {
        SSLCipher[] ciphers = JSSEngine.queryEnabledCipherSuites();
        String[] result = new String[ciphers.length];

        for (int i = 0; i < ciphers.length; i++) {
            result[i] = ciphers[i].toString();
        }

        return result;
    }

    public String[] getSupportedCipherSuites() {
        JSSEngineReferenceImpl engine = new JSSEngineReferenceImpl();
        return engine.getSupportedCipherSuites();
    }

    public JSSServerSocket createServerSocket() throws IOException {
        JSSServerSocket ret = new JSSServerSocket();
        ret.consumeSocket(new ServerSocket());
        ret.setSSLContext(ctx);
        ret.initEngine();
        ret.setKeyManager(key_manager);
        ret.setTrustManagers(trust_managers);

        return ret;
    }

    public JSSServerSocket createServerSocket(int port) throws IOException {
        JSSServerSocket ret = new JSSServerSocket();
        ret.consumeSocket(new ServerSocket(port));
        ret.setSSLContext(ctx);
        ret.initEngine();
        ret.setKeyManager(key_manager);
        ret.setTrustManagers(trust_managers);

        return ret;
    }

    public JSSServerSocket createServerSocket(int port, int backlog) throws IOException {
        JSSServerSocket ret = new JSSServerSocket();
        ret.consumeSocket(new ServerSocket(port, backlog));
        ret.setSSLContext(ctx);
        ret.initEngine();
        ret.setKeyManager(key_manager);
        ret.setTrustManagers(trust_managers);

        return ret;
    }

    public JSSServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException {
        JSSServerSocket ret = new JSSServerSocket();
        ret.consumeSocket(new ServerSocket(port, backlog, ifAddress));
        ret.setSSLContext(ctx);
        ret.initEngine();
        ret.setKeyManager(key_manager);
        ret.setTrustManagers(trust_managers);

        return ret;
    }
}
