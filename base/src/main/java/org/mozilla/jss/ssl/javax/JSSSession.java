package org.mozilla.jss.ssl.javax;

import java.lang.AutoCloseable;
import java.security.cert.Certificate;
import javax.security.cert.X509Certificate;
import java.security.Principal;
import java.util.HashMap;

import javax.net.ssl.*;

import org.mozilla.jss.nss.*;
import org.mozilla.jss.pkcs11.*;
import org.mozilla.jss.ssl.*;

public class JSSSession implements SSLSession, AutoCloseable {
    private static final int MAX_TLS_RECORD_PAYLOAD = (1 << 14);
    private JSSEngine parent;

    private int applicationBufferSize;
    private int packetBufferSize;

    private SSLCipher cipherSuite;
    private SSLVersion protocolVersion;

    private long creationTime;
    private long lastAccessTime;
    private long expirationTime;
    private byte[] sessionID;

    private HashMap<String, Object> appDataMap;

    private Certificate[] localCertificates;
    private Principal localPrincipal;

    private String peerHost;
    private int peerPort;

    private Principal peerPrincipal;
    private X509Certificate[] peerChain;
    private Certificate[] peerCertificates;

    private boolean closed;

    protected JSSSession(JSSEngine engine, int buffer_size) {
        this.parent = engine;

        applicationBufferSize = Math.min(buffer_size, MAX_TLS_RECORD_PAYLOAD);
        packetBufferSize = buffer_size;

        this.appDataMap = new HashMap<>();
    }

    public JSSEngine getEngine() {
        return parent;
    }

    public SSLChannelInfo getChannelInfo() {
        SSLFDProxy ssl_fd = parent.getSSLFDProxy();
        if (ssl_fd != null && ssl_fd.handshakeComplete) {
            return SSL.GetChannelInfo(ssl_fd);
        }

        return null;
    }

    public SSLPreliminaryChannelInfo getPreliminaryChannelInfo() {
        if (parent.getSSLFDProxy() != null) {
            return SSL.GetPreliminaryChannelInfo(parent.getSSLFDProxy());
        }

        return null;
    }

    @Override
    public int getApplicationBufferSize() {
        return applicationBufferSize;
    }

    @Override
    public int getPacketBufferSize() {
        return packetBufferSize;
    }

    @Override
    public byte[] getId() {
        return sessionID;
    }

    protected void setId(byte[] id) {
        sessionID = id;
    }

    @Override
    public SSLSessionContext getSessionContext() {
        return null;
    }

    @Override
    public long getCreationTime() {
        if (creationTime == 0) {
            refreshData();
        }

        return creationTime;
    }

    protected void setCreationTime(long time) {
        creationTime = time;
    }

    @Override
    public long getLastAccessedTime() {
        refreshData();
        return lastAccessTime;
    }

    protected void setLastAccessedTime(long when) {
        lastAccessTime = when;
    }

    public long getExpirationTime() {
        refreshData();
        return expirationTime;
    }

    protected void refreshData() {
        SSLChannelInfo info = getChannelInfo();
        if (info != null) {
            // NSS returns the values as seconds, but we have to report them
            // in milliseconds to our callers. Multiply by a thousand here.
            setId(info.getSessionID());
            setCreationTime(info.getCreationTime() * 1000);
            setLastAccessedTime(info.getLastAccessTime() * 1000);
            setExpirationTime(info.getExpirationTime() * 1000);

            setCipherSuite(info.getCipherSuite());
            setProtocol(info.getProtocolVersion());
        }
    }

    protected void setExpirationTime(long when) {
        expirationTime = when;
    }

    @Override
    public boolean isValid() {
        return !closed && System.currentTimeMillis() < getExpirationTime();
    }

    @Override
    public void invalidate() {
        if (parent.getSSLFDProxy() != null) {
             SSL.InvalidateSession(parent.getSSLFDProxy());
        }
    }

    @Override
    public void close() {
        closed = true;
        setPeerCertificates(null);
    }

    @Override
    public void putValue(String name, Object value) {
        if (appDataMap.containsKey(name)) {
            removeValue(name);
        }

        appDataMap.put(name, value);
        if (value instanceof SSLSessionBindingListener) {
            SSLSessionBindingListener listener = (SSLSessionBindingListener) value;
            listener.valueBound(new SSLSessionBindingEvent(this, name));
        }
    }

    @Override
    public Object getValue(String name) {
        return appDataMap.get(name);
    }

    @Override
    public void removeValue(String name) {
        Object value = appDataMap.remove(name);

        if (value instanceof SSLSessionBindingListener) {
            SSLSessionBindingListener listener = (SSLSessionBindingListener) value;
            listener.valueUnbound(new SSLSessionBindingEvent(this, name));
        }
    }

    @Override
    public String[] getValueNames() {
        return appDataMap.keySet().toArray(new String[0]);
    }

    @Override
    public Certificate[] getLocalCertificates() {
        return localCertificates;
    }

    protected void setLocalCertificates(Certificate[] certs) {
        localCertificates = certs;
    }

    @Override
    public Certificate[] getPeerCertificates() {
        return peerCertificates;
    }

    protected void setPeerCertificates(Certificate[] new_certs) {
        // Free existing certificates prior to setting new ones.
        if (peerCertificates != null) {
            for (Certificate cert : peerCertificates) {
                try {
                    ((PK11Cert) cert).close();
                } catch (Exception e) {
                    // We can't reasonably handle this exception. Raising
                    // a RuntimeException instead.
                    throw new RuntimeException(e.getMessage(), e);
                }
            }
        }

        peerCertificates = new_certs;
    }

    @Override
    public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        if (peerChain == null) {
            String msg = "Peer reported no certificate chain or handshake has not yet completed.";
            throw new SSLPeerUnverifiedException(msg);
        }

        return peerChain;
    }

    protected void setPeerCertificateChain(X509Certificate[] chain) {
        peerChain = chain;
    }

    @Override
    public Principal getPeerPrincipal() {
        return peerPrincipal;
    }

    protected void setPeerPrincipal(Principal principal) {
        peerPrincipal = principal;
    }

    @Override
    public Principal getLocalPrincipal() {
        return localPrincipal;
    }

    protected void setLocalPrincipal(Principal principal) {
        localPrincipal = principal;
    }

    @Override
    public String getCipherSuite() {
        if (cipherSuite == null) {
            refreshData();
        }

        if (cipherSuite == null) {
            return null;
        }

        return cipherSuite.name();
    }

    public SSLCipher getSSLCipher() {
        return cipherSuite;
    }

    protected void setCipherSuite(SSLCipher suite) {
        cipherSuite = suite;
    }

    @Override
    public String getProtocol() {
        if (protocolVersion == null) {
            refreshData();
        }

        if (protocolVersion == null) {
            return null;
        }

        return protocolVersion.jdkAlias();
    }

    public SSLVersion getSSLVersion() {
        return protocolVersion;
    }

    protected void setProtocol(SSLVersion protocol) {
        protocolVersion = protocol;
    }

    @Override
    public String getPeerHost() {
        return peerHost;
    }

    public void setPeerHost(String host) {
        peerHost = host;
    }

    @Override
    public int getPeerPort() {
        return peerPort;
    }

    public void setPeerPort(int port) {
        peerPort = port;
    }
}
