package org.mozilla.jss.tests;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.nss.Buffer;
import org.mozilla.jss.nss.BufferProxy;
import org.mozilla.jss.nss.PR;
import org.mozilla.jss.nss.PRErrors;
import org.mozilla.jss.nss.PRFDProxy;
import org.mozilla.jss.nss.SSL;
import org.mozilla.jss.nss.SSLFDProxy;
import org.mozilla.jss.nss.SecurityStatusResult;
import org.mozilla.jss.pkcs11.PK11Cert;
import org.mozilla.jss.pkcs11.PK11PrivKey;
import org.mozilla.jss.ssl.SSLAlertEvent;
import org.mozilla.jss.ssl.SSLVersion;
import org.mozilla.jss.ssl.SSLVersionRange;
import org.mozilla.jss.util.Password;

public class TestBufferPRFD {
    public static void TestCreateClose() {
        byte[] info = {0x01, 0x02, 0x03, 0x04};
        BufferProxy left_read = Buffer.Create(10);
        BufferProxy right_read = Buffer.Create(10);

        assert(left_read != null);
        assert(right_read != null);

        PRFDProxy left = PR.NewBufferPRFD(left_read, right_read, info);
        PRFDProxy right = PR.NewBufferPRFD(right_read, left_read, info);

        assert(left != null);
        assert(right != null);

        assert(PR.Write(left, info) == 4);
        assert(PR.Send(left, info, 0, 0) == 4);
        assert(PR.Send(left, info, 0, 0) == 2);

        byte[] result = PR.Recv(right, 10, 0, 0);
        assert(result.length == 10);

        for (int i = 0; i < 10; i++) {
            assert(result[i] == info[i % info.length]);
        }

        assert(PR.Close(left) == PR.SUCCESS);
        assert(PR.Close(right) == PR.SUCCESS);

        Buffer.Free(left_read);
        Buffer.Free(right_read);
    }

    public static SSLFDProxy Setup_NSS_Client(PRFDProxy fd, String host) throws Exception {
        SSLFDProxy result = SSL.ImportFD(null, fd);
        assert(result != null);

        assert(SSL.ResetHandshake(result, false) == SSL.SECSuccess);
        assert(SSL.SetURL(result, host) == SSL.SECSuccess);

        TestSSLVersionGetSet(result);

        return result;
    }

    public static SSLFDProxy Setup_NSS_Server(PRFDProxy fd, String host,
        PK11Cert cert, PK11PrivKey key) throws Exception
    {
        SSLFDProxy result = SSL.ImportFD(null, fd);
        assert(result != null);

        assert(SSL.ConfigServerCert(result, cert, key) == SSL.SECSuccess);
        assert(SSL.ConfigServerSessionIDCache(1, 100, 100, null) == SSL.SECSuccess);
        assert(SSL.ResetHandshake(result, true) == SSL.SECSuccess);
        assert(SSL.SetURL(result, host) == SSL.SECSuccess);

        TestSSLVersionGetSet(result);

        return result;
    }

    public static boolean IsHandshakeFinished(SSLFDProxy c_nspr, SSLFDProxy s_nspr) {
        SecurityStatusResult c_result = SSL.SecurityStatus(c_nspr);
        SecurityStatusResult s_result = SSL.SecurityStatus(s_nspr);

        assert(c_result != null && s_result != null);

        return c_result.on == 1 && s_result.on == 1;
    }

    public static void TestSSLVersionGetSet(SSLFDProxy s_nspr) throws Exception {
        SSLVersionRange initial = SSL.VersionRangeGet(s_nspr);
        System.out.println("Initial: (" + initial.getMinVersion() + ":" + initial.getMinEnum() + ", " + initial.getMaxVersion() + ":" + initial.getMaxEnum() + ")");

        SSLVersionRange vrange = new SSLVersionRange(SSLVersion.TLS_1_1, SSLVersion.TLS_1_3);

        assert(SSL.VersionRangeSet(s_nspr, vrange) == SSL.SECSuccess);

        SSLVersionRange actual = SSL.VersionRangeGet(s_nspr);
        System.out.println("Actual: (" + actual.getMinVersion() + ":" + actual.getMinEnum() + ", " + actual.getMaxVersion() + ":" + actual.getMaxEnum() + ")");
        assert(actual.getMinEnum() <= SSLVersion.TLS_1_2.value());
        assert(SSLVersion.TLS_1_2.value() <= actual.getMaxEnum());
    }

    public static void InitializeCM(String database, String password) throws Exception {
        CryptoManager manager;
        manager = CryptoManager.getInstance();
        manager.setPasswordCallback(new Password(password.toCharArray()));
    }

    public static void TestSSLHandshake(String server_nickname, String client_nickname) throws Exception
    {
        /* Constants */
        String host = "localhost";
        byte[] peer_info = host.getBytes();

        /* Find SSL Server Certificate */
        CryptoManager manager = CryptoManager.getInstance();
        PK11Cert server_cert = (PK11Cert) manager.findCertByNickname(server_nickname);
        PK11PrivKey server_key = (PK11PrivKey) manager.findPrivKeyByCert(server_cert);

        assert(server_cert != null);
        assert(server_cert instanceof PK11Cert);
        assert(server_key != null);
        assert(server_key instanceof PK11PrivKey);

        /* Find SSL Client Certificate, if nickname given. */
        PK11Cert client_cert = null;
        if (client_nickname != null) {
            client_cert = (PK11Cert) manager.findCertByNickname(client_nickname);
            assert(client_cert != null);
        }

        /* Create Buffers and BufferPRFDs */
        BufferProxy read_buf = Buffer.Create(1024);
        BufferProxy write_buf = Buffer.Create(1024);

        assert(read_buf != null);
        assert(write_buf != null);

        PRFDProxy c_buffer = PR.NewBufferPRFD(read_buf, write_buf, peer_info);
        PRFDProxy s_buffer = PR.NewBufferPRFD(write_buf, read_buf, peer_info);

        assert(c_buffer != null);
        assert(s_buffer != null);

        SSLFDProxy c_nspr = Setup_NSS_Client(c_buffer, host);
        SSLFDProxy s_nspr = Setup_NSS_Server(s_buffer, host, server_cert, server_key);

        assert(c_nspr != null);
        assert(s_nspr != null);

        /* Apply Client Certificate, if given. When given, request it as the
         * server. */
        if (client_cert != null) {
            c_nspr.SetClientCert(client_cert);
            assert(SSL.AttachClientCertCallback(c_nspr) == SSL.SECSuccess);

            assert(SSL.OptionSet(s_nspr, SSL.REQUEST_CERTIFICATE, 1) == SSL.SECSuccess);
        }

        /* Attach alert logging callback handler. */
        assert(SSL.EnableAlertLogging(c_nspr) == SSL.SECSuccess);
        assert(SSL.EnableAlertLogging(s_nspr) == SSL.SECSuccess);

        assert(!IsHandshakeFinished(c_nspr, s_nspr));

        /* Try a handshake */
        int count = 0;
        while(!IsHandshakeFinished(c_nspr, s_nspr)) {
            if (SSL.ForceHandshake(c_nspr) != SSL.SECSuccess) {
                int error = PR.GetError();

                if (error != PRErrors.WOULD_BLOCK_ERROR) {
                    System.out.println("Unexpected error: " + new String(PR.ErrorToName(error)) + " (" + error + ")");
                    System.exit(1);
                }
            }
            if (SSL.ForceHandshake(s_nspr) != SSL.SECSuccess) {
                int error = PR.GetError();

                if (error != PRErrors.WOULD_BLOCK_ERROR) {
                    System.out.println("Unexpected error: " + new String(PR.ErrorToName(error)) + " (" + error + ")");
                    System.exit(1);
                }
            }

            count += 1;
            if (count >= 40) {
                System.err.println("Error: unable to make progress after " + count + " steps!");
                System.exit(1);
            }
        }
        System.out.println("Handshake completed successfully!\n");
        assert(IsHandshakeFinished(c_nspr, s_nspr));

        /* Test peer data */
        assert(SSL.PeerCertificate(c_nspr) != null);
        assert(SSL.PeerCertificateChain(c_nspr) != null);

        if (client_nickname == null) {
            assert(SSL.PeerCertificate(s_nspr) == null);
            assert(SSL.PeerCertificateChain(s_nspr) == null);
        } else {
            assert(SSL.PeerCertificate(s_nspr) != null);
            assert(SSL.PeerCertificateChain(s_nspr) != null);
        }

        /* Send data from client -> server */
        byte[] client_message = "Cooking MCs".getBytes();

        assert(PR.Write(c_nspr, client_message) == client_message.length);
        byte[] server_received = PR.Read(s_nspr, client_message.length);
        assert(server_received != null);

        if (server_received.length != client_message.length) {
            System.out.println("Expected a client message of length " + client_message.length + " but got one of " + server_received.length);
            System.exit(1);
        }

        for (int i = 0; i < client_message.length && i < server_received.length; i++) {
            if (client_message[i] != server_received[i]) {
                System.out.println("Received byte " + server_received[i] + " on server but expected " + client_message[i]);
                System.exit(1);
            }
        }

        /* Send data from server -> client */
        byte[] server_message = "like a pound of bacon".getBytes();

        assert(PR.Write(s_nspr, server_message) == server_message.length);
        byte[] client_received = PR.Read(c_nspr, server_message.length);
        assert(client_received != null);

        if (client_received.length != server_message.length) {
            System.out.println("Expected a server message of length " + server_message.length + " but got one of " + client_received.length);
            System.exit(1);
        }

        for (int i = 0; i < server_message.length && i < client_received.length; i++) {
            if (server_message[i] != client_received[i]) {
                System.out.println("Received byte " + client_received[i] + " on client but expected " + server_message[i]);
                System.exit(1);
            }
        }

        /* Close connections */
        assert(PR.Shutdown(c_nspr, PR.SHUTDOWN_BOTH) == PR.SUCCESS);
        assert(PR.Shutdown(s_nspr, PR.SHUTDOWN_BOTH) == PR.SUCCESS);

        /* Print all alerts. */
        for (SSLAlertEvent alert : c_nspr.inboundAlerts) {
            System.err.println("client inbound: " + alert);
        }
        for (SSLAlertEvent alert : c_nspr.outboundAlerts) {
            System.err.println("client outbound: " + alert);
        }
        for (SSLAlertEvent alert : s_nspr.inboundAlerts) {
            System.err.println("server inbound: " + alert);
        }
        for (SSLAlertEvent alert : s_nspr.outboundAlerts) {
            System.err.println("server outbound: " + alert);
        }

        /* Clean up */
        assert(PR.Close(c_nspr) == PR.SUCCESS);
        assert(PR.Close(s_nspr) == PR.SUCCESS);

        Buffer.Free(read_buf);
        Buffer.Free(write_buf);
    }

    public static void main(String[] args) throws Exception {
        System.loadLibrary("jss");

        System.out.println("Calling TestCreateClose()...");
        TestCreateClose();

        System.out.println("Initializing CryptoManager...");
        InitializeCM(args[0], args[1]);

        System.out.println("Calling TestSSLHandshake(Server_RSA, null)...");
        TestSSLHandshake("Server_RSA", null);

        System.out.println("Calling TestSSLHandshake(Server_RSA, Client_RSA)...");
        TestSSLHandshake("Server_RSA", "Client_RSA");

        System.out.println("Calling TestSSLHandshake(Server_ECDSA, null)...");
        TestSSLHandshake("Server_ECDSA", null);

        System.out.println("Calling TestSSLHandshake(Server_ECDSA, Client_ECDSA)...");
        TestSSLHandshake("Server_ECDSA", "Client_ECDSA");
    }
}
