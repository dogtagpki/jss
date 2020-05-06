package org.mozilla.jss.ssl.javax;

import java.io.*;
import java.net.*;
import java.security.*;

import javax.net.ssl.*;

import org.mozilla.jss.provider.javax.crypto.JSSKeyManager;
import org.mozilla.jss.ssl.SSLCipher;

public class JSSSocketFactory extends SSLSocketFactory {
    private SSLContext ctx;
    private JSSKeyManager key_manager;
    private X509TrustManager[] trust_managers;

    public JSSSocketFactory(String protocol, JSSKeyManager km, X509TrustManager[] tms) {
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

    public JSSSocket createSocket() throws IOException {
        JSSSocket ret = new JSSSocket();
        ret.consumeSocket(new Socket());
        ret.setSSLContext(ctx);
        ret.initEngine();
        ret.setKeyManager(key_manager);
        ret.setTrustManagers(trust_managers);

        return ret;
    }

    public JSSSocket createSocket(InetAddress host, int port) throws IOException {
        JSSSocket ret = new JSSSocket();
        ret.consumeSocket(new Socket(host, port));
        ret.setSSLContext(ctx);
        ret.initEngine();
        ret.setKeyManager(key_manager);
        ret.setTrustManagers(trust_managers);

        return ret;
    }

    public JSSSocket createSocket(InetAddress host, int port, InetAddress localAddress, int localPort) throws IOException {
        JSSSocket ret = new JSSSocket();
        ret.consumeSocket(new Socket(host, port, localAddress, localPort));
        ret.setSSLContext(ctx);
        ret.initEngine();
        ret.setKeyManager(key_manager);
        ret.setTrustManagers(trust_managers);

        return ret;
    }

    public JSSSocket createSocket(String host, int port) throws IOException {
        JSSSocket ret = new JSSSocket();
        ret.consumeSocket(new Socket(host, port));
        ret.setSSLContext(ctx);
        ret.initEngine(host, port);
        ret.setKeyManager(key_manager);
        ret.setTrustManagers(trust_managers);

        return ret;
    }

    public JSSSocket createSocket(String host, int port, InetAddress localAddress, int localPort) throws IOException {
        JSSSocket ret = new JSSSocket();
        ret.consumeSocket(new Socket(host, port, localAddress, localPort));
        ret.setSSLContext(ctx);
        ret.initEngine(host, port);
        ret.setKeyManager(key_manager);
        ret.setTrustManagers(trust_managers);

        return ret;
    }

    public JSSSocket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        JSSSocket ret = new JSSSocket();
        ret.consumeSocket(s);
        ret.setSSLContext(ctx);
        ret.initEngine(host, port);
        ret.setAutoClose(autoClose);
        ret.setKeyManager(key_manager);
        ret.setTrustManagers(trust_managers);

        return ret;
    }

    public JSSSocket createSocket(Socket s, InputStream consumed, boolean autoClose) throws IOException {
        JSSSocket ret = new JSSSocket();
        ret.consumeSocket(s);
        ret.setConsumedData(consumed);
        ret.setSSLContext(ctx);
        ret.initEngine();
        ret.setUseClientMode(false);
        ret.setAutoClose(autoClose);
        ret.setKeyManager(key_manager);
        ret.setTrustManagers(trust_managers);

        return ret;
    }
}
