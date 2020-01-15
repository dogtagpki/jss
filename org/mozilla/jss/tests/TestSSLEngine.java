package org.mozilla.jss.tests;

import java.lang.*;
import java.nio.*;
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
        CryptoManager.initialize(args[0]);
        CryptoManager cm = CryptoManager.getInstance();
        cm.setPasswordCallback(new FilePasswordCallback(args[1]));
    }

    public static void testProvided() throws Exception {
        SSLContext ctx = SSLContext.getDefault();
        System.err.println(ctx.getProvider());

        SSLEngine raw_eng = ctx.createSSLEngine();
        assert(raw_eng instanceof JSSEngine);
    }

    public static JSSParameters createParameters(String alias) throws Exception {
        JSSParameters params = new JSSParameters();

        params.setProtocols(SSLVersion.TLS_1_2, SSLVersion.TLS_1_3);
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
        return tmf.getTrustManagers();
    }

    public static void testHandshake(JSSEngine client_eng, JSSEngine server_eng) throws Exception {
        // Ensure we exit in case of a bug... :-)
        int counter = 0;
        int max_steps = 20;
        int max_data = client_eng.getSession().getApplicationBufferSize();

        boolean client_done = false;
        boolean server_done = false;

        ArrayList<ByteBuffer> c2s_buffers = new ArrayList<ByteBuffer>();
        ArrayList<ByteBuffer> s2c_buffers = new ArrayList<ByteBuffer>();
        for (counter = 0; counter < max_steps; counter++) {
            SSLEngineResult.HandshakeStatus client_state = client_eng.getHandshakeStatus();
            SSLEngineResult.HandshakeStatus server_state = server_eng.getHandshakeStatus();
            System.err.println("client_done=" + client_done + " | client_eng.getHandshakeStatus()=" + client_state + " | c2s_buffers.size=" + c2s_buffers.size());
            System.err.println("server_done=" + server_done + " | server_eng.getHandshakeStatus()=" + server_state + " | s2c_buffers.size=" + s2c_buffers.size());

            System.err.println("\n\n=====BEGIN CLIENT=====");

            if (!client_done && client_state == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                ByteBuffer src = null;
                ByteBuffer dst = ByteBuffer.allocate(max_data);

                SSLEngineResult r = client_eng.wrap(src, dst);
                dst.flip();

                if (r.getStatus() != SSLEngineResult.Status.OK) {
                    throw new RuntimeException("Unknown result from client_eng.wrap(): " + r.getStatus());
                } else if (dst.hasRemaining()) {
                    // Since we flipped our buffer, we can use hasRemaining()
                    // to check if there's data we should unwrap on the client
                    // side. There is, so add it to the candidates.
                    c2s_buffers.add(dst);
                }
            } else if (!client_done && client_state == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                while (s2c_buffers.size() > 0) {
                    ByteBuffer src = s2c_buffers.remove(0);
                    ByteBuffer dst = null;

                    SSLEngineResult r = client_eng.unwrap(src, dst);
                    if (r.getStatus() != SSLEngineResult.Status.OK) {
                        throw new RuntimeException("Unknown result from client_eng.unwrap(): " + r.getStatus());
                    } else if (src.hasRemaining()) {
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
            } else if (!client_done) {
                throw new RuntimeException("Unknown status for client_eng: " + client_state);
            }

            System.err.println("=====END CLIENT=====\n\n");
            System.err.println("\n\n=====BEGIN SERVER=====");

            if (!server_done && server_state == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                ByteBuffer src = null;
                ByteBuffer dst = ByteBuffer.allocate(max_data);

                SSLEngineResult r = server_eng.wrap(src, dst);
                dst.flip();

                if (r.getStatus() != SSLEngineResult.Status.OK) {
                    throw new RuntimeException("Unknown result from server_eng.wrap(): " + r.getStatus());
                } else if (dst.hasRemaining()) {
                    // Since we flipped our buffer, we can use hasRemaining()
                    // to check if there's data we should unwrap on the client
                    // side. There is, so add it to the candidates.
                    s2c_buffers.add(dst);
                }
            } else if (!server_done && server_state == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                while (c2s_buffers.size() > 0) {
                    ByteBuffer src = c2s_buffers.remove(0);
                    ByteBuffer dst = null;

                    SSLEngineResult r = server_eng.unwrap(src, dst);
                    if (r.getStatus() != SSLEngineResult.Status.OK) {
                        throw new RuntimeException("Unknown result from server_eng.unwrap(): " + r.getStatus());
                    } else if (src.hasRemaining()) {
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
            } else if (!server_done) {
                throw new RuntimeException("Unknown status for server handshake status: " + server_state);
            }
            System.err.println("=====END SERVER=====\n\n");

            if (client_done && server_done) {
                assert(c2s_buffers.size() == 0);
                assert(s2c_buffers.size() == 0);

                break;
            }
        }

        if (counter == max_steps) {
            throw new RuntimeException("Unable to complete a handshake in " + max_steps + " steps; assuming we were stuck in an infinite loop: c2s_buffers.size=" + c2s_buffers.size() + " s2c_buffers.size=" + s2c_buffers.size());
        }
    }

    public static void testSendData(JSSEngine send, JSSEngine recv, ByteBuffer mesg, ByteBuffer inter, ByteBuffer dest) throws Exception {
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
            } else if (inter.hasRemaining()) {
                break;
            }
        }
        if (counter == max_counter) {
            throw new RuntimeException("Reasonably expected to get encrypted data during wrap.");
        }

        System.err.println("Bytes of ciphertext message: " + inter.remaining());
        assert(inter.remaining() >= mesg_size);

        r = recv.unwrap(inter, dest);
        dest.flip();

        if (r.getStatus() != SSLEngineResult.Status.OK) {
            throw new RuntimeException("Unknown result from send.wrap(): " + r.getStatus());
        } else if (!dest.hasRemaining()) {
            throw new RuntimeException("Reasonably expected to get encrypted data during unwrap.");
        }

        System.err.println("Bytes of decrypted message: " + dest.remaining());

        mesg.position(start_pos);
        byte[] orig = new byte[dest.remaining()];
        byte[] copy = new byte[dest.remaining()];

        mesg.get(orig);
        dest.get(copy);

        if (!Arrays.equals(orig, copy)) {
            throw new RuntimeException("Expected data received to equal that sent!");
        }
    }

    public static void testPostHandshakeTransfer(JSSEngine client_eng, JSSEngine server_eng) throws Exception {
        assert(client_eng.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING || client_eng.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED);
        assert(server_eng.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING || server_eng.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED);

        // Ensure we exit in case of a bug... :-)
        int counter = 0;
        int max_data = client_eng.getSession().getApplicationBufferSize();

        ByteBuffer client_msg = ByteBuffer.wrap("Cooking MCs".getBytes());
        ByteBuffer c2s_buffer = ByteBuffer.allocate(max_data);
        ByteBuffer server_unwrap = ByteBuffer.allocate(max_data);
        testSendData(client_eng, server_eng, client_msg, c2s_buffer, server_unwrap);

        ByteBuffer server_msg = ByteBuffer.wrap("like a pound of bacon".getBytes());
        ByteBuffer s2c_buffer = ByteBuffer.allocate(max_data);
        ByteBuffer client_unwrap = ByteBuffer.allocate(max_data);
        testSendData(server_eng, client_eng, server_msg, s2c_buffer, client_unwrap);
    }

    public static void sendData(JSSEngine send, JSSEngine recv) throws Exception {
        int counter = 0;
        int max_tries = 20;
        int max_data = send.getSession().getApplicationBufferSize();

        ByteBuffer src = null;
        ByteBuffer transfer = ByteBuffer.allocate(max_data);
        ByteBuffer read = ByteBuffer.allocate(max_data);

        SSLEngineResult r = null;

        for (counter = 0; counter < max_tries; counter++) {
            r = send.wrap(src, transfer);
            transfer.flip();

            if (r.getStatus() != SSLEngineResult.Status.OK) {
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

        if (r.getStatus() != SSLEngineResult.Status.OK) {
            throw new RuntimeException("Unknown result from recv.unwrap(): " + r.getStatus());
        } else if (read.hasRemaining()) {
            throw new RuntimeException("Expected not to recieve any data but got " + read.remaining() + " bytes during unwrap.");
        }
    }

    public static void testClose(JSSEngine client_eng, JSSEngine server_eng) throws Exception {
        assert(client_eng.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING || client_eng.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED);
        assert(server_eng.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING || server_eng.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED);
        assert(client_eng.getStatus().on == 1);
        assert(server_eng.getStatus().on == 1);
        assert(client_eng.isInboundDone() == false);
        assert(server_eng.isInboundDone() == false);

        client_eng.closeOutbound();
        assert(client_eng.isOutboundDone() == true);
        sendData(client_eng, server_eng);
        assert(server_eng.isInboundDone() == true);

        server_eng.closeOutbound();
        assert(server_eng.isOutboundDone() == true);
        sendData(server_eng, client_eng);
        assert(client_eng.isInboundDone() == true);
    }

    public static void testBasicHandshake(SSLContext ctx, String client_alias, String server_alias) throws Exception {
        JSSEngine client_eng = (JSSEngine) ctx.createSSLEngine();
        client_eng.setSSLParameters(createParameters(client_alias));
        client_eng.setUseClientMode(true);
        client_eng.beginHandshake();

        System.err.println("client_eng protocols: ");
        for (String version : client_eng.getEnabledProtocols()) {
            System.err.println(" - " + version);
        }

        JSSEngine server_eng = (JSSEngine) ctx.createSSLEngine();
        server_eng.setSSLParameters(createParameters(server_alias));
        server_eng.setUseClientMode(false);
        server_eng.beginHandshake();

        testHandshake(client_eng, server_eng);
        testPostHandshakeTransfer(client_eng, server_eng);
        testClose(client_eng, server_eng);
    }

    public static void testBasicClientServer(String[] args) throws Exception {
        SSLContext ctx = SSLContext.getDefault();
        ctx.init(getKMs(), getTMs(), null);

        String client_alias = args[2];
        String server_alias = args[3];

        testBasicHandshake(ctx, client_alias, server_alias);
    }

    public static void testNativeClientServer(String[] args) throws Exception {
        SSLContext ctx = SSLContext.getDefault();
        ctx.init(getKMs(), new TrustManager[] { new JSSNativeTrustManager() }, null);

        String client_alias = args[2];
        String server_alias = args[3];

        testBasicHandshake(ctx, client_alias, server_alias);
    }

    public static void main(String[] args) throws Exception {
        // Args:
        //  - nssdb
        //  - nssdb password
        //  - client cert
        //  - server cert

        System.out.println("Initializing CryptoManager...");
        initialize(args);

        System.out.println("Testing provided instance...");
        testProvided();

        System.out.println("Testing basic handshake with TMs from provider...");
        testBasicClientServer(args);

        System.out.println("Testing basic handshake with native TM...");
        testBasicClientServer(args);
    }
}
