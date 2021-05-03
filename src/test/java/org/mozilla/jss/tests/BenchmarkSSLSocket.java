package org.mozilla.jss.tests;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.ArrayList;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.provider.javax.crypto.JSSKeyManager;
import org.mozilla.jss.provider.javax.crypto.JSSNativeTrustManager;

/**
 * Utility for benchmarking the performance of SSLSocket implementations.
 *
 * For information about using this benchmark, see the documentation in this
 * repo at: /docs/usage/benchmarksslsocket.md
 */
public class BenchmarkSSLSocket {
    public String type;
    public String nickname;
    public String password;
    public int port;
    public int size;

    public String headers = "HTTP/1.1 200 OK\r\nConnection: Closed\r\n";
    public String message;

    public int limit = 150;

    public BenchmarkSSLSocket(String type, String nickname, int port, int size) throws Exception {
        this.type = type;
        this.nickname = nickname;
        this.port = port;
        this.size = size;
        this.limit = limit;

        headers = headers + "Content-Length: " + size + "\r\n";

        StringBuilder sb = new StringBuilder(size);
        for (int i = 0; i < size; i++) {
            sb.append("a");
        }

        message = headers + "\r\n" + sb.toString();
    }

    public BenchmarkSSLSocket(String type, String nickname, String password, int port, int size) throws Exception {
        this(type, nickname, port, size);
        this.password = password;
    }

    public ServerSocket getServerSocket() throws Exception {
        System.err.println("Constructing socket...");
        switch (type) {
            case "JSS.legacy": {
                org.mozilla.jss.ssl.SSLServerSocket sock = new org.mozilla.jss.ssl.SSLServerSocket(port);
                sock.setSoTimeout(0);
                org.mozilla.jss.ssl.SSLServerSocket.configServerSessionIDCache(0, 43200, 43200, null);

                sock.setReuseAddress(true);
                sock.requestClientAuth(false);
                sock.requireClientAuth(org.mozilla.jss.ssl.SSLSocket.SSL_REQUIRE_NEVER);
                sock.setUseClientMode(false);
                sock.setServerCertNickname(nickname);

                return sock;
            }
            case "JSS.SSLSocket": {
                KeyManagerFactory kmf = KeyManagerFactory.getInstance("NssX509");

                SSLContext ctx = SSLContext.getInstance("TLS", "Mozilla-JSS");
                ctx.init(
                    kmf.getKeyManagers(),
                    new TrustManager[] { new JSSNativeTrustManager() },
                    null
                );

                SSLServerSocketFactory factory = ctx.getServerSocketFactory();
                org.mozilla.jss.ssl.javax.JSSServerSocket sock = (org.mozilla.jss.ssl.javax.JSSServerSocket) factory.createServerSocket(port);

                sock.setReuseAddress(true);
                sock.setWantClientAuth(false);
                sock.setNeedClientAuth(false);
                sock.setUseClientMode(false);
                sock.setCertFromAlias(nickname);

                return sock;
            }
            case "SunJSSE.SSLSocket": {
                FileInputStream fis = new FileInputStream(nickname);
                KeyStore store = KeyStore.getInstance("PKCS12");
                store.load(fis, "m1oZilla".toCharArray());

                // Courtesy of https://stackoverflow.com/questions/537040/how-to-connect-to-a-secure-website-using-ssl-in-java-with-a-pkcs12-file
                // Without using a JKS-type KeyStore for the TrustManager,
                // constructing a TrustManagerFactory will consume 100% CPU
                // and we won't reach the SSLServerSocketFactory code.
                KeyStore jks = KeyStore.getInstance("JKS");
                jks.load(null);

                KeyStore ks = store;
                for (java.util.Enumeration<String> t = ks.aliases(); t.hasMoreElements(); ) {
                    String alias = t.nextElement();
                    if (ks.isKeyEntry(alias)) {
                        java.security.cert.Certificate[] a = ks.getCertificateChain(alias);
                        // i = 1 skips the CA certificate
                        for (int i = 1; i < a.length; i++) {
                            java.security.cert.X509Certificate x509 = (java.security.cert.X509Certificate) a[i];
                            jks.setCertificateEntry(x509.getSubjectDN().toString(), x509);
                        }
                    }
                }

                KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                kmf.init(store, "m1oZilla".toCharArray());
                TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
                tmf.init(jks);

                SSLContext ctx = SSLContext.getInstance("TLS", "SunJSSE");
                ctx.init(
                    kmf.getKeyManagers(),
                    tmf.getTrustManagers(),
                    null
                );

                SSLServerSocketFactory factory = ctx.getServerSocketFactory();
                javax.net.ssl.SSLServerSocket sock = (javax.net.ssl.SSLServerSocket) factory.createServerSocket(port);

                sock.setReuseAddress(true);
                sock.setWantClientAuth(false);
                sock.setNeedClientAuth(false);
                sock.setUseClientMode(false);

                return sock;
            }
            default:
                throw new RuntimeException("Unknown socket type: `" + type + "` -- expected one of `JSS.SSLSocket`, `JSS.legacy`, or `SunJSSE.SSLSocket`.");
        }
    }

    class PeerTask implements Runnable {
        Socket peer;
        byte[] message;

        public PeerTask(Socket peer, String message) {
            this.peer = peer;
            this.message = message.getBytes();
        }

        public void run() {
            try {
                try {
                    // First, force a handshake
                    if (peer instanceof org.mozilla.jss.ssl.SSLSocket) {
                        org.mozilla.jss.ssl.SSLSocket sock = (org.mozilla.jss.ssl.SSLSocket) peer;
                        sock.setUseClientMode(false);
                        sock.forceHandshake();
                    } else if (peer instanceof javax.net.ssl.SSLSocket) {
                        javax.net.ssl.SSLSocket sock = (javax.net.ssl.SSLSocket) peer;
                        sock.setUseClientMode(false);
                        sock.startHandshake();
                    }

                    // Consume all input data.
                    InputStream is = peer.getInputStream();
                    byte[] in_data = new byte[is.available()];
                    is.read(in_data);

                    // Send our message back.
                    OutputStream os = peer.getOutputStream();
                    os.write(message);
                } finally {
                    peer.close();
                }
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage(), e);
            }
        }
    }

    public void run() throws Exception {
        ArrayList<Thread> existing = new ArrayList<Thread>(limit);

        try (
            ServerSocket server_socket = getServerSocket();
        ) {
            System.err.println("Listening for connections...");
            while (true) {
                int length = existing.size();
                while (length > limit) {
                    int index = 0;

                    while (index < length) {
                        Thread.sleep(10);

                        if (existing.get(index).isAlive()) {
                            index += 1;
                        } else {
                            existing.remove(index);
                            length -= 1;
                        }
                    }
                }

                Socket peer_socket = server_socket.accept();
                Runnable task = new PeerTask(peer_socket, message);
                Thread thread = new Thread(task);
                thread.start();
            }
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 4 || args.length > 5) {
            System.err.println("Usage: BenchmarkSSLSocket <type> [...args...]");
            System.err.println("type: JSS.SSLSocket, JSS.legacy, or SunJSSE.SSLSocket\n");

            System.err.println("When type is JSS.SSLSocket or JSS.legacy:");
            System.err.println("Usage: BenchmarkSSLSocket <type> <alias> <port> <size>");
            System.err.println("alias: server certificate nickname");
            System.err.println("port: What server port to listen on");
            System.err.println("size: bytes of body to send in reply (plus header size)\n");

            System.err.println("When type is SunJSSE.SSLSocket:");
            System.err.println("Usage: BenchmarkSSLSocket SunJSSE.SSLSocket <p12path> [<p12pass>] <port> <size>");
            System.err.println("p12path: path to the p12 file containing the server cert");
            System.err.println("p12pass: password to access p12 file with; default: m1oZilla");
            System.err.println("port: What server port to listen on");
            System.err.println("size: bytes of body to send in reply (plus header size)\n");
            System.exit(1);
        }

        BenchmarkSSLSocket benchmark;
        if (args.length == 4) {
            String type = args[0];
            String alias = args[1];
            int port = Integer.parseInt(args[2]);
            int size = Integer.parseInt(args[3]);
            benchmark = new BenchmarkSSLSocket(type, alias, "m1oZilla", port, size);
        } else {
            String type = args[0];
            String path = args[1];
            String password = args[2];
            int port = Integer.parseInt(args[3]);
            int size = Integer.parseInt(args[4]);
            benchmark = new BenchmarkSSLSocket(type, path, password, port, size);
        }

        benchmark.run();
    }
}
