package org.mozilla.jss.ssl.javax;

import java.security.cert.Certificate;
import javax.security.cert.X509Certificate;
import java.security.Principal;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLPeerUnverifiedException;

public class JSSSession implements SSLSession {
    private int application_buffer_size;
    private String cipher_suite;
    private long creation_time;
    private byte[] session_id;
    private long last_access_time;
    private Certificate[] local_certificates;
    private Principal local_principal;
    private int packet_buffer_size;
    private X509Certificate[] peer_chain;
    private Certificate[] peer_certificates;
    private String peer_host;
    private int peer_port;
    private Principal peer_principal;
    private String protocol;

    JSSSession(int buffer_size) {
        creation_time = System.currentTimeMillis();
        application_buffer_size = buffer_size;
        packet_buffer_size = buffer_size;
        setLastAccessedTime();
    }

    public byte[] getId() {
        return session_id;
    }

    protected void setId(byte[] new_id) {
        session_id = new_id;
        setLastAccessedTime();
    }

    public SSLSessionContext getSessionContext() {
        return null;
    }

    public long getCreationTime() {
        return creation_time;
    }

    public long getLastAccessedTime() {
        return last_access_time;
    }

    protected void setLastAccessedTime() {
        last_access_time = System.currentTimeMillis();
    }

    public void invalidate() {}
    public boolean isValid() { return true; }
    public void putValue(String name, Object value) {}
    public Object getValue(String name) { return null; }
    public void removeValue(String name) {}
    public String[] getValueNames() { return null; }

    public Certificate[] getPeerCertificates() {
        return peer_certificates;
    }

    protected void setPeerCertificates(Certificate[] new_certs) {
        peer_certificates = new_certs;
        setLastAccessedTime();
    }

    public Certificate[] getLocalCertificates() {
        return local_certificates;
    }

    protected void setLocalCertificates(Certificate[] new_certs) {
        local_certificates = new_certs;
        setLastAccessedTime();
    }

    public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        if (peer_chain == null) {
            throw new SSLPeerUnverifiedException("");
        }
        return peer_chain;
    }

    protected void setPeerCertificateChain(X509Certificate[] new_chain) {
        peer_chain = new_chain;
        setLastAccessedTime();
    }

    public Principal getPeerPrincipal() {
        return peer_principal;
    }

    protected void setPeerPrincipal(Principal new_principal) {
        peer_principal = new_principal;
        setLastAccessedTime();
    }

    public Principal getLocalPrincipal() {
        return local_principal;
    }

    protected void setLocalPrincipal(Principal new_principal) {
        local_principal = new_principal;
        setLastAccessedTime();
    }

    public String getCipherSuite() {
        return cipher_suite;
    }

    protected void setCipherSuite(String new_suite) {
        cipher_suite = new_suite;
        setLastAccessedTime();
    }

    public String getProtocol() {
        return protocol;
    }

    protected void setProtocol(String new_protocol) {
        protocol = new_protocol;
        setLastAccessedTime();
    }

    public String getPeerHost() {
        return peer_host;
    }

    public void setPeerHost(String new_host) {
        peer_host = new_host;
        setLastAccessedTime();
    }

    public int getPeerPort() {
        return peer_port;
    }

    public void setPeerPort(int new_port) {
        peer_port = new_port;
        setLastAccessedTime();
    }

    public int getPacketBufferSize() {
        return packet_buffer_size;
    }

    public int getApplicationBufferSize() {
        return application_buffer_size;
    }
}
