package org.mozilla.jss.tests;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.util.Arrays;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.provider.javax.crypto.JSSNativeTrustManager;
import org.mozilla.jss.ssl.javax.JSSParameters;
import org.mozilla.jss.ssl.javax.JSSSocket;

public class TestJSSSocketChannel {

    static X509KeyManager[] keyManagers;
    static X509TrustManager[] trustManagers;

    public static void initialize(String[] args) throws Exception {
        CryptoManager cm = CryptoManager.getInstance();
        cm.setPasswordCallback(new FilePasswordCallback(args[1]));

        KeyStore ks = KeyStore.getInstance("PKCS11", "Mozilla-JSS");
        ks.load(null, null);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("NssX509", "Mozilla-JSS");
        kmf.init(ks, null);

        KeyManager[] kms = kmf.getKeyManagers();
        keyManagers = new X509KeyManager[kms.length];
        for (int i = 0; i < kms.length; i++) {
            keyManagers[i] = (X509KeyManager) kms[i];
        }

        trustManagers = new X509TrustManager[] { new JSSNativeTrustManager() };
    }

    static JSSSocket createJSSSocket(SSLContext ctx, Socket raw, String alias, boolean clientMode, int port) throws Exception {
        JSSSocket sock = new JSSSocket();
        sock.consumeSocket(raw);
        sock.setSSLContext(ctx);
        if (clientMode) {
            sock.initEngine("localhost", port);
        } else {
            sock.initEngine();
        }
        JSSParameters params = new JSSParameters();
        params.setAliases(Arrays.asList(alias.split(",")));
        params.setHostname("localhost");
        sock.setSSLParameters(params);
        sock.setUseClientMode(clientMode);
        sock.setKeyManagers(keyManagers);
        sock.setTrustManagers(trustManagers);
        return sock;
    }

    static byte[] readWithRetry(InputStream in, long timeoutMs) throws Exception {
        byte[] buf = new byte[4096];
        long deadline = System.currentTimeMillis() + timeoutMs;
        int total = 0;
        while (total == 0) {
            if (System.currentTimeMillis() > deadline) {
                throw new IOException("Read timed out after " + timeoutMs + "ms");
            }
            int n = in.read(buf, total, buf.length - total);
            if (n < 0) {
                throw new IOException("Unexpected EOF");
            }
            total += n;
            if (total == 0) {
                Thread.sleep(50);
            }
        }
        return Arrays.copyOf(buf, total);
    }

    static byte[] readExactly(InputStream in, int count, long timeoutMs) throws Exception {
        byte[] buf = new byte[count];
        long deadline = System.currentTimeMillis() + timeoutMs;
        int total = 0;
        while (total < count) {
            if (System.currentTimeMillis() > deadline) {
                throw new IOException("Read timed out after " + timeoutMs + "ms (got " + total + " of " + count + " bytes)");
            }
            int n = in.read(buf, total, count - total);
            if (n < 0) {
                throw new IOException("Unexpected EOF after " + total + " of " + count + " bytes");
            }
            if (n == 0) {
                Thread.sleep(50);
            }
            total += n;
        }
        return buf;
    }

    static void assertEqual(String expected, byte[] actual, String context) {
        String actualStr = new String(actual);
        if (!expected.equals(actualStr)) {
            throw new RuntimeException(context + ": expected '" + expected + "', got '" + actualStr + "'");
        }
    }

    public static void testPostHandshakeAuth(SSLContext ctx, String clientAlias, String serverAlias) throws Exception {
        System.out.println("TestJSSSocketChannel: testPostHandshakeAuth");

        final Exception[] serverError = { null };

        ServerSocket ss = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        int port = ss.getLocalPort();

        Thread serverThread = new Thread(() -> {
            try {
                Socket rawServer = ss.accept();
                JSSSocket server = createJSSSocket(ctx, rawServer, serverAlias, false, 0);
                server.setEnabledProtocols(new String[] { "TLSv1.3" });

                server.startHandshake();
                System.out.println("  server: initial handshake complete");

                OutputStream sOut = server.getOutputStream();
                InputStream sIn = server.getInputStream();

                sOut.write("hello from server".getBytes());
                sOut.flush();

                assertEqual("hello from client", readWithRetry(sIn, 10000), "server initial read");
                System.out.println("  server: initial data exchange OK");

                // Enable client auth and trigger post-handshake auth
                server.setWantClientAuth(true);
                server.setNeedClientAuth(true);
                server.startHandshake();

                sOut.write("post-auth data".getBytes());
                sOut.flush();
                System.out.println("  server: sent post-handshake-auth data");

                assertEqual("post-auth reply", readWithRetry(sIn, 10000), "server post-auth read");

                SSLSession session = server.getSession();
                assert session.getPeerCertificates() != null : "Expected peer certificates";
                assert session.getPeerCertificates().length > 0 : "Expected at least one peer certificate";
                System.out.println("  server: verified " + session.getPeerCertificates().length + " peer cert(s)");

                // Send >18KB to verify large writes work after
                // post-handshake auth.
                byte[] largeData = new byte[32 * 1024];
                for (int i = 0; i < largeData.length; i++) {
                    largeData[i] = (byte) (i & 0xFF);
                }
                sOut.write(largeData);
                sOut.flush();
                System.out.println("  server: sent " + largeData.length + " bytes post-auth");

                assertEqual("large-data-ok", readWithRetry(sIn, 10000), "server large data ack");

                // Signal the client it is OK to close now. This prevents
                // the client's close_notify from arriving while the server
                // is still processing the post-handshake auth response.
                sOut.write("done".getBytes());
                sOut.flush();

                server.close();
            } catch (Exception e) {
                serverError[0] = e;
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();

        try {
            Socket rawClient = new Socket(InetAddress.getLoopbackAddress(), port);
            JSSSocket client = createJSSSocket(ctx, rawClient, clientAlias, true, port);
            client.setEnabledProtocols(new String[] { "TLSv1.3" });

            client.startHandshake();
            System.out.println("  client: initial handshake complete");

            OutputStream cOut = client.getOutputStream();
            InputStream cIn = client.getInputStream();

            assertEqual("hello from server", readWithRetry(cIn, 10000), "client initial read");

            cOut.write("hello from client".getBytes());
            cOut.flush();
            System.out.println("  client: initial data exchange OK");

            // This read triggers post-handshake auth processing
            // in JSSSocketChannel.read() → flushPostHandshake()
            assertEqual("post-auth data", readWithRetry(cIn, 10000), "client post-auth read");
            System.out.println("  client: post-handshake auth completed transparently");

            cOut.write("post-auth reply".getBytes());
            cOut.flush();

            // Receive the large (>18KB) post-auth transfer
            int largeSize = 32 * 1024;
            byte[] largeReceived = readExactly(cIn, largeSize, 10000);
            for (int i = 0; i < largeSize; i++) {
                if (largeReceived[i] != (byte) (i & 0xFF)) {
                    throw new RuntimeException("Large data mismatch at byte " + i);
                }
            }
            System.out.println("  client: received and verified " + largeSize + " bytes post-auth");
            cOut.write("large-data-ok".getBytes());
            cOut.flush();

            // Wait for server ack before closing, so close_notify doesn't
            // race with the server's read of the post-handshake auth response.
            assertEqual("done", readWithRetry(cIn, 10000), "client done-ack read");

            client.close();
        } finally {
            serverThread.join(30000);
            ss.close();
        }

        if (serverError[0] != null) {
            throw new RuntimeException("Server thread failed", serverError[0]);
        }

        if (serverThread.isAlive()) {
            throw new RuntimeException("Server thread did not finish in time");
        }

        System.out.println("TestJSSSocketChannel: testPostHandshakeAuth PASSED");
    }

    public static void testMultipleMessagesAfterPostHandshakeAuth(SSLContext ctx, String clientAlias, String serverAlias) throws Exception {
        System.out.println("TestJSSSocketChannel: testMultipleMessagesAfterPostHandshakeAuth");

        final Exception[] serverError = { null };

        ServerSocket ss = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        int port = ss.getLocalPort();

        Thread serverThread = new Thread(() -> {
            try {
                Socket rawServer = ss.accept();
                JSSSocket server = createJSSSocket(ctx, rawServer, serverAlias, false, 0);
                server.setEnabledProtocols(new String[] { "TLSv1.3" });

                server.startHandshake();

                OutputStream sOut = server.getOutputStream();
                InputStream sIn = server.getInputStream();

                // Initial data exchange to settle the connection
                sOut.write("ping".getBytes());
                sOut.flush();
                assertEqual("pong", readWithRetry(sIn, 10000), "server initial read");

                // Trigger post-handshake auth
                server.setWantClientAuth(true);
                server.setNeedClientAuth(true);
                server.startHandshake();

                sOut.write("auth-trigger".getBytes());
                sOut.flush();

                assertEqual("ack", readWithRetry(sIn, 10000), "server ack read");

                // Multiple round trips after post-handshake auth
                for (int i = 0; i < 5; i++) {
                    String msg = "server-msg-" + i;
                    sOut.write(msg.getBytes());
                    sOut.flush();

                    String expected = "client-msg-" + i;
                    assertEqual(expected, readWithRetry(sIn, 10000), "server round " + i);
                }

                sOut.write("done".getBytes());
                sOut.flush();

                server.close();
            } catch (Exception e) {
                serverError[0] = e;
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();

        try {
            Socket rawClient = new Socket(InetAddress.getLoopbackAddress(), port);
            JSSSocket client = createJSSSocket(ctx, rawClient, clientAlias, true, port);
            client.setEnabledProtocols(new String[] { "TLSv1.3" });

            client.startHandshake();

            OutputStream cOut = client.getOutputStream();
            InputStream cIn = client.getInputStream();

            assertEqual("ping", readWithRetry(cIn, 10000), "client initial read");
            cOut.write("pong".getBytes());
            cOut.flush();

            assertEqual("auth-trigger", readWithRetry(cIn, 10000), "client auth-trigger read");

            cOut.write("ack".getBytes());
            cOut.flush();

            // Multiple round trips after post-handshake auth
            for (int i = 0; i < 5; i++) {
                String expected = "server-msg-" + i;
                assertEqual(expected, readWithRetry(cIn, 10000), "client round " + i);

                String msg = "client-msg-" + i;
                cOut.write(msg.getBytes());
                cOut.flush();
            }

            assertEqual("done", readWithRetry(cIn, 10000), "client done-ack read");

            client.close();
        } finally {
            serverThread.join(30000);
            ss.close();
        }

        if (serverError[0] != null) {
            throw new RuntimeException("Server thread failed", serverError[0]);
        }

        if (serverThread.isAlive()) {
            throw new RuntimeException("Server thread did not finish in time");
        }

        System.out.println("TestJSSSocketChannel: testMultipleMessagesAfterPostHandshakeAuth PASSED");
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Initializing CryptoManager...");
        initialize(args);

        if (!org.mozilla.jss.JSSProvider.ENABLE_JSSENGINE) {
            System.out.println("JSSEngine not enabled, skipping.");
            return;
        }

        String clientAlias = args[2];
        String serverAlias = args[3];

        // Check TLS 1.3 support
        SSLContext ctx = SSLContext.getInstance("TLS", "Mozilla-JSS");
        ctx.init(keyManagers, trustManagers, null);

        String[] supported = ctx.createSSLEngine().getSupportedProtocols();
        boolean tls13 = false;
        for (String p : supported) {
            if ("TLSv1.3".equals(p)) {
                tls13 = true;
                break;
            }
        }
        if (!tls13) {
            System.out.println("TLS 1.3 not supported, skipping.");
            return;
        }

        testPostHandshakeAuth(ctx, clientAlias, serverAlias);
        testMultipleMessagesAfterPostHandshakeAuth(ctx, clientAlias, serverAlias);
    }
}
