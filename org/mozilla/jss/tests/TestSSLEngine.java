package org.mozilla.jss.tests;

import java.lang.*;
import java.nio.*;
import java.net.*;
import java.util.*;
import java.security.*;
import javax.net.ssl.*;

import org.mozilla.jss.*;
import org.mozilla.jss.nss.*;
import org.mozilla.jss.ssl.*;
import org.mozilla.jss.ssl.javax.*;
import org.mozilla.jss.provider.javax.crypto.*;

public class TestSSLEngine {
    public static void initialize(String[] args) throws Exception {
        CryptoManager cm = CryptoManager.getInstance();
        cm.setPasswordCallback(new FilePasswordCallback(args[1]));
    }

    public static void testProvided() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS", "Mozilla-JSS");
        System.err.println(ctx.getProvider());

        SSLEngine raw_eng = ctx.createSSLEngine();
        assert(raw_eng instanceof JSSEngine);
    }

    public static JSSParameters createParameters() throws Exception {
        JSSParameters params = new JSSParameters();

        params.setHostname("localhost");

        return params;
    }

    public static JSSParameters createParameters(String alias) throws Exception {
        JSSParameters params = new JSSParameters();

        params.setAlias(alias);
        params.setHostname("localhost");

        return params;
    }

    public static KeyManager[] getKMs() throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("NssX509");
        return kmf.getKeyManagers();
    }

    public static TrustManager[] getTMs() throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("NssX509");
        TrustManager[] tms = tmf.getTrustManagers();
        for (TrustManager tm : tms) {
            if (tm instanceof JSSTrustManager) {
                // JSS test suite doesn't enable extended key usages, so
                // configure the TrustManager to allow them.
                JSSTrustManager jtm = (JSSTrustManager) tm;
                jtm.configureAllowMissingExtendedKeyUsage(true);
            }
        }

        return tms;
    }

    public static void testHandshake(SSLEngine client_eng, SSLEngine server_eng) throws Exception {
        // Ensure we exit in case of a bug... :-)
        int counter = 0;
        int max_steps = 20;
        int max_data = Math.max(client_eng.getSession().getApplicationBufferSize(), server_eng.getSession().getApplicationBufferSize());
        max_data = Math.max(max_data, 1 << 20);

        boolean client_done = false;
        boolean server_done = false;

        client_eng.beginHandshake();
        server_eng.beginHandshake();

        ArrayList<ByteBuffer> c2s_buffers = new ArrayList<ByteBuffer>();
        ArrayList<ByteBuffer> s2c_buffers = new ArrayList<ByteBuffer>();
        for (counter = 0; counter < max_steps; counter++) {
            SSLEngineResult.HandshakeStatus client_state = client_eng.getHandshakeStatus();
            SSLEngineResult.HandshakeStatus server_state = server_eng.getHandshakeStatus();
            System.err.println("client_done=" + client_done + " | client_eng.getHandshakeStatus()=" + client_state + " | c2s_buffers.size=" + c2s_buffers.size());
            System.err.println("server_done=" + server_done + " | server_eng.getHandshakeStatus()=" + server_state + " | s2c_buffers.size=" + s2c_buffers.size());

            System.err.println("\n\n=====BEGIN CLIENT=====");

            if (!client_done && client_state == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                ByteBuffer src = ByteBuffer.allocate(0);
                ByteBuffer dst = ByteBuffer.allocate(max_data);

                SSLEngineResult r = client_eng.wrap(src, dst);
                if (r.getStatus() != SSLEngineResult.Status.OK) {
                    throw new RuntimeException("Unknown result from client_eng.wrap(): " + r.getStatus());
                }

                dst.flip();
                if (dst.hasRemaining()) {
                    // Since we flipped our buffer, we can use hasRemaining()
                    // to check if there's data we should unwrap on the client
                    // side. There is, so add it to the candidates.
                    c2s_buffers.add(dst);
                }
            } else if (!client_done && client_state == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                while (s2c_buffers.size() > 0) {
                    ByteBuffer src = s2c_buffers.remove(0);
                    ByteBuffer dst = ByteBuffer.allocate(max_data);

                    SSLEngineResult r = client_eng.unwrap(src, dst);
                    if (r.getStatus() != SSLEngineResult.Status.OK) {
                        throw new RuntimeException("Unknown result from client_eng.unwrap(): " + r.getStatus());
                    }

                    dst.flip();
                    assert(!dst.hasRemaining());
                    if (src.hasRemaining()) {
                        // Since we have bytes left after reading it, put it
                        // back on the front of the stack.
                        s2c_buffers.add(0, src);

                        // After only partially reading a buffer, it is
                        // unlikely that we'll be able to continue, so break.
                        break;
                    } else if (r.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                        break;
                    }
                }
            } else if (counter > 1 && !client_done && (client_state == SSLEngineResult.HandshakeStatus.FINISHED || client_state == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING)) {
                System.err.println("Client: " + server_eng.getHandshakeStatus());
                client_done = true;
            } else if (!client_done && client_state == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                /* Per SSLEngineSimpleDemo from Oracle. */
                Runnable runnable;
                while ((runnable = client_eng.getDelegatedTask()) != null) {
                    System.err.println("Client: running delegated task");
                    runnable.run();
                }

                client_state = client_eng.getHandshakeStatus();
                assert(client_state != SSLEngineResult.HandshakeStatus.NEED_TASK);
            } else if (!client_done) {
                throw new RuntimeException("Unknown status for client_eng: " + client_state);
            } else if (client_done && s2c_buffers.size() > 0) {
                System.err.println("Client: processing remaining buffers.");
                while (s2c_buffers.size() > 0) {
                    ByteBuffer src = s2c_buffers.remove(0);
                    ByteBuffer dst = ByteBuffer.allocate(max_data);

                    SSLEngineResult r = client_eng.unwrap(src, dst);
                    if (r.getStatus() != SSLEngineResult.Status.OK) {
                        throw new RuntimeException("Unknown result from client_eng.unwrap(): " + r.getStatus());
                    }

                    dst.flip();
                    assert(!dst.hasRemaining());
                    if (src.hasRemaining()) {
                        // Since we have bytes left after reading it, put it
                        // back on the front of the stack.
                        s2c_buffers.add(0, src);

                        // After only partially reading a buffer, it is
                        // unlikely that we'll be able to continue, so break.
                        break;
                    } else if (r.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                        break;
                    }
                }
            }

            System.err.println("=====END CLIENT=====\n\n");
            System.err.println("\n\n=====BEGIN SERVER=====");

            if (!server_done && server_state == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                ByteBuffer src = ByteBuffer.allocate(0);
                ByteBuffer dst = ByteBuffer.allocate(max_data);

                SSLEngineResult r = server_eng.wrap(src, dst);
                if (r.getStatus() != SSLEngineResult.Status.OK) {
                    throw new RuntimeException("Unknown result from server_eng.wrap(): " + r.getStatus());
                }

                dst.flip();
                if (dst.hasRemaining()) {
                    // Since we flipped our buffer, we can use hasRemaining()
                    // to check if there's data we should unwrap on the client
                    // side. There is, so add it to the candidates.
                    s2c_buffers.add(dst);
                }
            } else if (!server_done && server_state == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                while (c2s_buffers.size() > 0) {
                    ByteBuffer src = c2s_buffers.remove(0);
                    ByteBuffer dst = ByteBuffer.allocate(max_data);

                    SSLEngineResult r = server_eng.unwrap(src, dst);
                    if (r.getStatus() != SSLEngineResult.Status.OK) {
                        throw new RuntimeException("Unknown result from server_eng.unwrap(): " + r.getStatus());
                    }

                    dst.flip();
                    assert(!dst.hasRemaining());
                    if (src.hasRemaining()) {
                        // Since we have bytes left after reading it, put it
                        // back on the front of the stack.
                        c2s_buffers.add(0, src);

                        // After only partially reading a buffer, it is
                        // unlikely that we'll be able to continue, so break.
                        break;
                    } else if (r.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                        break;
                    }
                }
            } else if (counter > 1 && !server_done && (server_state == SSLEngineResult.HandshakeStatus.FINISHED || server_state == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING)) {
                System.err.println("Server: " + server_eng.getHandshakeStatus());
                server_done = true;
            } else if (!server_done && server_state == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                /* Per SSLEngineSimpleDemo from Oracle. */
                Runnable runnable;
                while ((runnable = server_eng.getDelegatedTask()) != null) {
                    System.err.println("Server: running delegated task");
                    runnable.run();
                }

                server_state = client_eng.getHandshakeStatus();
                assert(server_state != SSLEngineResult.HandshakeStatus.NEED_TASK);
            } else if (!server_done) {
                throw new RuntimeException("Unknown status for server handshake status: " + server_state);
            } else if (server_done && c2s_buffers.size() > 0) {
                System.err.println("Server: processing remaining buffers.");
                while (c2s_buffers.size() > 0) {
                    ByteBuffer src = c2s_buffers.remove(0);
                    ByteBuffer dst = ByteBuffer.allocate(max_data);;

                    SSLEngineResult r = server_eng.unwrap(src, dst);
                    if (r.getStatus() != SSLEngineResult.Status.OK) {
                        throw new RuntimeException("Unknown result from server_eng.unwrap(): " + r.getStatus());
                    }

                    dst.flip();
                    assert(!dst.hasRemaining());
                    if (src.hasRemaining()) {
                        // Since we have bytes left after reading it, put it
                        // back on the front of the stack.
                        c2s_buffers.add(0, src);

                        // After only partially reading a buffer, it is
                        // unlikely that we'll be able to continue, so break.
                        break;
                    } else if (r.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                        break;
                    }
                }
            }
            System.err.println("=====END SERVER=====\n\n");

            if (client_done && server_done) {
                assert(s2c_buffers.size() == 0);
                assert(c2s_buffers.size() == 0);
                break;
            }
        }

        if (counter == max_steps) {
            throw new RuntimeException("Unable to complete a handshake in " + max_steps + " steps; assuming we were stuck in an infinite loop: c2s_buffers.size=" + c2s_buffers.size() + " s2c_buffers.size=" + s2c_buffers.size());
        }
    }

    public static void sendTestData(SSLEngine send, SSLEngine recv, ByteBuffer mesg, ByteBuffer inter, ByteBuffer dest) throws Exception {
        int start_pos = mesg.position();
        int mesg_size = mesg.remaining();
        int counter = 0;
        int max_counter = 10;

        SSLEngineResult r;

        for (counter = 0; counter < max_counter; counter++) {
            r = send.wrap(mesg, inter);
            inter.flip();

            System.err.println("Bytes of plaintext message: " + mesg_size);

            if (r.getStatus() != SSLEngineResult.Status.OK) {
                throw new RuntimeException("Unknown result from send.wrap(): " + r.getStatus());
            } else if (mesg.hasRemaining()) {
                // Need to be called again to add more data.
                inter.flip();
                continue;
            } else if (inter.hasRemaining()) {
                break;
            }
        }

        if (counter == max_counter) {
            throw new RuntimeException("Reasonably expected to get encrypted data during wrap.");
        }

        System.err.println("Bytes of ciphertext message: " + inter.remaining());
        assert(inter.remaining() >= mesg_size);
        assert(dest.remaining() > inter.remaining());

        for (counter = 0; counter < max_counter; counter++) {
            r = recv.unwrap(inter, dest);
            dest.flip();

            if (r.getStatus() != SSLEngineResult.Status.OK) {
                throw new RuntimeException("Unknown result from send.wrap(): " + r.getStatus());
            } else if (!dest.hasRemaining()) {
                throw new RuntimeException("Reasonably expected to get decrypted data during unwrap. Have: " + dest.remaining());
            } else if (dest.remaining() < mesg_size) {
                // Flip it back so we can append more data again.
                System.err.println("Expecting to get " + (mesg_size - dest.remaining()) + " more bytes... Calling unwrap again.");
                dest.flip();
                continue;
            } else if (dest.remaining() >= mesg_size) {
                break;
            }
        }

        if (counter == max_counter) {
            throw new RuntimeException("Reasonably expected to get all decrypted data during unwrap but only got " + dest.remaining());
        }

        System.err.println("Bytes of decrypted message: " + dest.remaining());

        mesg.position(start_pos);
        byte[] orig = new byte[mesg.remaining()];
        byte[] copy = new byte[dest.remaining()];

        mesg.get(orig);
        dest.get(copy);

        if (!Arrays.equals(orig, copy)) {
            throw new RuntimeException("Expected data received to equal that sent!");
        }
    }

    public static void testPostHandshakeTransfer(SSLEngine client_eng, SSLEngine server_eng) throws Exception {
        assert(client_eng.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING);
        assert(server_eng.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING);

        int max_data = Math.max(client_eng.getSession().getApplicationBufferSize(), server_eng.getSession().getApplicationBufferSize());
        max_data = Math.max(max_data, 1 << 25);


        System.err.println("Testing post-handshake transfer...");

        ByteBuffer client_msg = ByteBuffer.wrap("Cooking MCs".getBytes());
        ByteBuffer c2s_buffer = ByteBuffer.allocate(max_data);
        ByteBuffer server_unwrap = ByteBuffer.allocate(max_data);
        sendTestData(client_eng, server_eng, client_msg, c2s_buffer, server_unwrap);

        ByteBuffer server_msg = ByteBuffer.wrap("like a pound of bacon.".getBytes());
        ByteBuffer s2c_buffer = ByteBuffer.allocate(max_data);
        ByteBuffer client_unwrap = ByteBuffer.allocate(max_data);
        sendTestData(server_eng, client_eng, server_msg, s2c_buffer, client_unwrap);

        System.err.println("Done testing post-handshake transfer! Success!");
    }

    public static void sendCloseData(SSLEngine send, SSLEngine recv) throws Exception {
        int counter = 0;
        int max_tries = 20;
        int max_data = Math.max(send.getSession().getApplicationBufferSize(), recv.getSession().getApplicationBufferSize());
        max_data = Math.max(max_data, 1 << 20);

        ByteBuffer src = ByteBuffer.allocate(max_data);
        ByteBuffer transfer = ByteBuffer.allocate(max_data);
        ByteBuffer read = ByteBuffer.allocate(max_data);

        SSLEngineResult r = null;

        for (counter = 0; counter < max_tries; counter++) {
            r = send.wrap(src, transfer);
            transfer.flip();

            if (r.getStatus() != SSLEngineResult.Status.OK && r.getStatus() != SSLEngineResult.Status.CLOSED) {
                throw new RuntimeException("Unknown result from send.wrap(): " + r.getStatus());
            } else if (transfer.hasRemaining()) {
                break;
            }
        }

        if (counter == max_tries) {
            throw new RuntimeException("Reasonably expected to send CLOSE_NOTIFY alert to other party.");
        }

        r = recv.unwrap(transfer, read);
        read.flip();

        if (r.getStatus() != SSLEngineResult.Status.OK && r.getStatus() != SSLEngineResult.Status.CLOSED) {
            throw new RuntimeException("Unknown result from recv.unwrap(): " + r.getStatus());
        } else if (read.hasRemaining()) {
            throw new RuntimeException("Expected not to recieve any data but got " + read.remaining() + " bytes during unwrap.");
        }
    }

    public static void testClose(SSLEngine client_eng, SSLEngine server_eng) throws Exception {
        assert(client_eng.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING || client_eng.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED);
        assert(server_eng.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING || server_eng.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED);
        if (client_eng instanceof JSSEngine) {
            assert(((JSSEngine) client_eng).getStatus().on >= 1);
        }

        if (server_eng instanceof JSSEngine) {
            assert(((JSSEngine) server_eng).getStatus().on >= 1);
        }

        assert(client_eng.isInboundDone() == false);
        assert(client_eng.isOutboundDone() == false);
        assert(server_eng.isInboundDone() == false);
        assert(server_eng.isOutboundDone() == false);

        System.err.println("Testing client close...");

        client_eng.closeOutbound();
        sendCloseData(client_eng, server_eng);
        assert(client_eng.isOutboundDone() == true);
        assert(server_eng.isInboundDone() == true);
        assert(server_eng.isOutboundDone() == false);
        assert(client_eng.isInboundDone() == false);

        System.err.println("Testing server close...");

        server_eng.closeOutbound();
        sendCloseData(server_eng, client_eng);

        // Everything should be done now...
        assert(server_eng.isOutboundDone() == true);
        assert(client_eng.isInboundDone() == true);

        System.err.println("Passed close test!");
    }

    public static void testBasicHandshake(SSLEngine client_eng, SSLEngine server_eng) throws Exception {
        testHandshake(client_eng, server_eng);
        testPostHandshakeTransfer(client_eng, server_eng);
        testClose(client_eng, server_eng);
    }

    public static void configureSSLEngine(SSLEngine eng, String protocol, String cipher_suite) throws Exception {
        eng.setEnabledProtocols(new String[] { protocol });
        eng.setEnabledCipherSuites(new String[] { cipher_suite });
    }

    public static boolean skipProtocolCipherSuite(String protocol, String cipher_suite, String client_alias, String server_alias) {
        SSLVersion v = SSLVersion.findByAlias(protocol);
        SSLCipher cs = SSLCipher.valueOf(cipher_suite);

        boolean works_with_version = cs.supportsTLSVersion(v);
        boolean is_rsa = client_alias.contains("RSA") && cs.requiresRSACert();
        boolean is_ecdsa = client_alias.contains("ECDSA") && cs.requiresECDSACert();
        boolean supported = cs.isSupported();
        boolean null_cipher = cipher_suite.contains("NULL");
        boolean right_cert_type = is_rsa || is_ecdsa;

        // The JSS test suite currently doesn't generate certificates
        // compatible with ECDH_RSA cipher suites.
        boolean is_ecdh_rsa = cipher_suite.contains("ECDH_RSA");

        return (!works_with_version || !supported || !right_cert_type || null_cipher || is_ecdh_rsa);
    }

    public static void testAllHandshakes(SSLContext ctx, String client_alias, String server_alias, boolean client_auth) throws Exception {
        SSLEngine dummy = ctx.createSSLEngine();
        assert(dummy != null);

        for (String protocol : dummy.getSupportedProtocols()) {
            for (String cipher_suite : dummy.getSupportedCipherSuites()) {
                if (skipProtocolCipherSuite(protocol, cipher_suite, client_alias, server_alias)) {
                    continue;
                }

                System.err.println("Testing: " + protocol + " with " + cipher_suite);

                String context = protocol + "/" + cipher_suite;

                JSSEngine client_eng = (JSSEngine) ctx.createSSLEngine();
                client_eng.setSSLParameters(createParameters(client_alias));
                client_eng.setUseClientMode(true);

                if (client_eng instanceof JSSEngineReferenceImpl) {
                    ((JSSEngineReferenceImpl) client_eng).setName("JSS Client " + context);
                }

                JSSEngine server_eng = (JSSEngine) ctx.createSSLEngine();
                server_eng.setSSLParameters(createParameters(server_alias));
                server_eng.setUseClientMode(false);

                if (server_eng instanceof JSSEngineReferenceImpl) {
                    ((JSSEngineReferenceImpl) server_eng).setName("JSS Server " + context);
                    ((JSSEngineReferenceImpl) server_eng).enableSafeDebugLogging(7377);
                }

                if (client_auth) {
                    server_eng.setNeedClientAuth(true);
                }

                configureSSLEngine(client_eng, protocol, cipher_suite);
                configureSSLEngine(server_eng, protocol, cipher_suite);

                try {
                    testBasicHandshake(client_eng, server_eng);
                } catch (Exception e) {
                    client_eng.cleanup();
                    server_eng.cleanup();
                    throw e;
                }
            }
        }
    }

    public static void testJSSEToJSSHandshakes(SSLContext jss_context, String server_alias) throws Exception {
        // We set this up as a JSS Server with JSSE client, forgoing client
        // authentication. Begin by setting up the JSSE context, complete with
        // supported protocols.
        SSLContext jsse_context = SSLContext.getInstance("TLS", "SunJSSE");
        jsse_context.init(getKMs(), getTMs(), null);
        SSLEngine jsse_dummy = jsse_context.createSSLEngine();

        String[] jsse_protocols = jsse_dummy.getSupportedProtocols();
        Arrays.sort(jsse_protocols);

        String[] jsse_suites = jsse_dummy.getSupportedCipherSuites();
        Arrays.sort(jsse_suites);

        SSLEngine dummy = jss_context.createSSLEngine();
        for (String protocol : dummy.getSupportedProtocols()) {
            for (String cipher_suite : dummy.getSupportedCipherSuites()) {
                if (skipProtocolCipherSuite(protocol, cipher_suite, "", server_alias)) {
                    continue;
                }

                if (Arrays.binarySearch(jsse_protocols, protocol) < 0) {
                    System.err.println("JSSE doesn't support protocol: " + protocol);
                    continue;
                }

                if (Arrays.binarySearch(jsse_suites, cipher_suite) < 0) {
                    System.err.println("JSSE doesn't support this cipher suite: " + cipher_suite);
                    continue;
                }

                System.err.println("Testing JSSE client with JSS server: " + protocol + " with " + cipher_suite);

                SSLEngine client_eng = jsse_context.createSSLEngine();
                client_eng.setSSLParameters(createParameters());
                client_eng.setUseClientMode(true);

                JSSEngine server_eng = (JSSEngine) jss_context.createSSLEngine();
                server_eng.setSSLParameters(createParameters(server_alias));
                server_eng.setUseClientMode(false);

                if (server_eng instanceof JSSEngineReferenceImpl) {
                    ((JSSEngineReferenceImpl) server_eng).enableSafeDebugLogging(7374);
                }

                configureSSLEngine(client_eng, protocol, cipher_suite);
                configureSSLEngine(server_eng, protocol, cipher_suite);

                try {
                    testBasicHandshake(client_eng, server_eng);
                } catch (Exception e) {
                    server_eng.cleanup();
                    throw e;
                }
            }
        }
    }

    public static void testBasicClientServer(String[] args) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS", "Mozilla-JSS");
        ctx.init(getKMs(), getTMs(), null);

        String client_alias = args[2];
        String server_alias = args[3];

        testAllHandshakes(ctx, client_alias, server_alias, false);
        testAllHandshakes(ctx, client_alias, server_alias, true);
        testJSSEToJSSHandshakes(ctx, server_alias);
    }

    public static void testNativeClientServer(String[] args) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS", "Mozilla-JSS");
        ctx.init(getKMs(), new TrustManager[] { new JSSNativeTrustManager() }, null);

        String client_alias = args[2];
        String server_alias = args[3];

        testAllHandshakes(ctx, client_alias, server_alias, false);
        testAllHandshakes(ctx, client_alias, server_alias, true);
        testJSSEToJSSHandshakes(ctx, server_alias);
    }

    public static void main(String[] args) throws Exception {
        // Args:
        //  - nssdb
        //  - nssdb password
        //  - client cert
        //  - server cert

        System.out.println("Initializing CryptoManager...");
        initialize(args);

        assert(SSLVersion.TLS_1_2.matchesAlias("TLSv1.2"));

        System.out.println("Testing provided instance...");
        testProvided();

        System.out.println("Testing basic handshake with TMs from provider...");
        testBasicClientServer(args);

        System.out.println("Testing basic handshake with native TM...");
        testNativeClientServer(args);
    }
}
