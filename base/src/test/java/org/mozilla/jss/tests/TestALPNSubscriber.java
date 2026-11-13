/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.tests;

import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.pkix.cert.Certificate;
import org.mozilla.jss.pkix.cert.CertificateInfo;
import org.mozilla.jss.pkix.cert.Extension;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;
import org.mozilla.jss.ssl.javax.JSSParameters;
import org.mozilla.jss.ssl.javax.JSSServerSocket;
import org.mozilla.jss.ssl.javax.JSSServerSocketFactory;
import org.mozilla.jss.ssl.javax.JSSSocket;
import org.mozilla.jss.ssl.javax.JSSSocketFactory;
import org.mozilla.jss.util.X509ExtensionUtil;
import org.mozilla.jss.netscape.security.x509.DNSName;
import org.mozilla.jss.netscape.security.x509.GeneralName;
import org.mozilla.jss.netscape.security.x509.GeneralNames;
import org.mozilla.jss.netscape.security.x509.SubjectAlternativeNameExtension;

/**
 * Demonstration / integration test for the RFC 8737 TLS-ALPN-01 mechanism.
 *
 * Unlike TestSSLEngine's testALPNHandshake() (which proves generic ALPN
 * negotiation using in-memory buffer-backed JSSEngine instances and an
 * ordinary CA-signed cert), this test exercises the actual classes and
 * cert shape the real PKI TLSALPN01Validator will use:
 *
 *   - A real loopback TCP connection via JSSSocket/JSSServerSocket (not
 *     in-memory buffers).
 *   - A self-signed certificate carrying the RFC 8737 "acmeIdentifier"
 *     extension, built here the same way a real ACME client would.
 *   - A client that installs a permissive X509TrustManager (since the
 *     cert is deliberately self-signed) and checks the extension's
 *     digest after the handshake, the same sequence the real validator
 *     sketch follows.
 *
 * The client side here is the stand-in for our ACME server acting as
 * validator; the server side is the stand-in for the subscriber.
 */
public class TestALPNSubscriber {

    private static final String ALPN_PROTOCOL = "acme-tls/1";

    // id-pe-acmeIdentifier, RFC 8737 Section 3.
    private static final OBJECT_IDENTIFIER ACME_IDENTIFIER_OID =
        new OBJECT_IDENTIFIER(new long[] { 1, 3, 6, 1, 5, 5, 7, 1, 31 });
    private static final String ACME_IDENTIFIER_OID_STRING = "1.3.6.1.5.5.7.1.31";

    private static final OBJECT_IDENTIFIER SUBJECT_ALT_NAME_OID =
      new OBJECT_IDENTIFIER(new long[] { 2, 5, 29, 17 });

    private static void log(String msg) {
        System.err.println("TestALPNSubscriber: " + msg);
    }

    /**
     * Build a self-signed certificate carrying the acmeIdentifier
     * extension with the given digest.
     *
     * Per RFC 8737, the extension's content is itself an OCTET STRING
     * wrapping the 32-byte digest -- on top of the outer OCTET STRING
     * wrapper every X.509 extension's value is already DER-encoded as.
     * So this cert's extnValue is "doubly wrapped," matching exactly what
     * a real ACME client would produce.
     */
    private static Certificate makeChallengeCert(String hostname, int serialNumber,
            PrivateKey privKey, PublicKey pubKey, SignatureAlgorithm sigAlg,
            byte[] digest) throws Exception {

        log("makeChallengeCert: building extension for OID " + ACME_IDENTIFIER_OID
            + " with digest length " + digest.length);

        OCTET_STRING innerDigest = new OCTET_STRING(digest);
        OCTET_STRING extnValue = new OCTET_STRING(ASN1Util.encode(innerDigest));
        Extension acmeExt = new Extension(ACME_IDENTIFIER_OID, true, extnValue);

        SEQUENCE extensions = new SEQUENCE();

        //Add SAN

        GeneralNames names = new GeneralNames();
        names.add(new GeneralName(new DNSName(hostname)));
        SubjectAlternativeNameExtension sanExtension =
            new SubjectAlternativeNameExtension(false, names);
        OCTET_STRING sanExtnValue = new OCTET_STRING(sanExtension.getExtensionValue());
        Extension sanExt = new Extension(SUBJECT_ALT_NAME_OID, false, sanExtnValue);


        extensions.addElement(acmeExt);
        extensions.addElement(sanExt);

        AlgorithmIdentifier sigAlgID = new AlgorithmIdentifier(sigAlg.toOID(), null);

        // Self-signed: issuer == subject.
        Name name = new Name();
        name.addCountryName("US");
        name.addOrganizationName("Mozilla");
        name.addOrganizationalUnitName("JSS Testing");
        name.addCommonName(hostname);

        Calendar cal = Calendar.getInstance();
        Date notBefore = cal.getTime();
        cal.add(Calendar.HOUR, 1);
        Date notAfter = cal.getTime();

        SubjectPublicKeyInfo.Template spkiTemp = new SubjectPublicKeyInfo.Template();
        SubjectPublicKeyInfo spki =
            (SubjectPublicKeyInfo) ASN1Util.decode(spkiTemp, pubKey.getEncoded());

        CertificateInfo info = new CertificateInfo(
            CertificateInfo.v3, new INTEGER(serialNumber), sigAlgID,
            name, notBefore, notAfter, name, spki);
        info.setExtensions(extensions);

        log("makeChallengeCert: signing self-signed cert for CN=" + hostname
            + " serial=" + serialNumber);
        Certificate cert = new Certificate(info, privKey, sigAlg);
        log("makeChallengeCert: done");
        return cert;
    }

    public static void testSubscriberValidation(String hostname) throws Exception {
        log("=== starting testSubscriberValidation(hostname=" + hostname + ") ===");

        // 1. Compute a test "key authorization" digest -- stands in for
        //    token + account-key-thumbprint in a real ACME exchange.
        byte[] keyAuth = "test-token.test-account-thumbprint".getBytes(StandardCharsets.UTF_8);
        byte[] expectedDigest = MessageDigest.getInstance("SHA-256").digest(keyAuth);
        log("step 1: computed expected digest (" + expectedDigest.length + " bytes)");

        // 2. Generate and import the self-signed challenge cert -- this
        //    stands in for what the subscriber's ACME client would do
        //    before announcing readiness.
        log("step 2: initializing CryptoManager / key storage token");
        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken tok = cm.getInternalKeyStorageToken();

        log("step 2: generating RSA-2048 key pair for the challenge cert");
        java.security.KeyPairGenerator kpg =
            java.security.KeyPairGenerator.getInstance("RSA", "Mozilla-JSS");
        kpg.initialize(2048);
        KeyPair pair = kpg.genKeyPair();
        log("step 2: key pair generated");

        Certificate challengeCert = makeChallengeCert(hostname, 9001,
            pair.getPrivate(), pair.getPublic(),
            SignatureAlgorithm.RSASignatureWithSHA256Digest, expectedDigest);

        String challengeAlias = "ACME_Challenge_Cert";
        log("step 2: importing challenge cert under alias [" + challengeAlias + "]");
        cm.importCertPackage(ASN1Util.encode(challengeCert), challengeAlias);
        log("step 2: challenge cert imported successfully");

        // 3. Stand up a real server socket presenting that cert and
        //    offering only acme-tls/1 -- the subscriber stand-in.
        log("step 3: creating server-side SSLContext");
        SSLContext serverCtx = SSLContext.getInstance("TLS", "Mozilla-JSS");
        serverCtx.init(TestSSLEngine.getKMs(), null, null);

        JSSServerSocketFactory serverFactory =
            (JSSServerSocketFactory) serverCtx.getServerSocketFactory();
        JSSServerSocket serverSocket =
            (JSSServerSocket) serverFactory.createServerSocket(0);
        log("step 3: server socket created, binding cert alias and ALPN protocol");
        serverSocket.setCertFromAlias(challengeAlias);
        serverSocket.setUseClientMode(false);

        JSSParameters serverParams = (JSSParameters) serverSocket.getSSLParameters();
        serverParams.setApplicationProtocols(new String[] { ALPN_PROTOCOL });
        serverSocket.setSSLParameters(serverParams);

        int port = serverSocket.getLocalPort();
        log("step 3: server (subscriber stand-in) listening on localhost:" + port);

        final Exception[] serverError = new Exception[1];
        Thread serverThread = new Thread(() -> {
            try {
                log("[server thread] waiting for incoming connection...");
                JSSSocket accepted = serverSocket.accept();
                log("[server thread] connection accepted, starting handshake");
                accepted.setUseClientMode(false);   // Ensure server mode explicitly. 

                accepted.startHandshake();
                log("[server thread] handshake complete; negotiated protocol: ["
                    + accepted.getApplicationProtocol() + "]");
                InputStream in = accepted.getInputStream();
                in.read();
                log("[server thread] closing accepted socket");
                accepted.close();
                log("[server thread] done, no errors");
            } catch (Exception e) {
                log("[server thread] FAILED: " + e);
                serverError[0] = e;
            }
        });
        serverThread.start();

        // 4. Client side -- the stand-in for our ACME server acting as
        //    validator. Accept the self-signed cert on purpose, offer
        //    only acme-tls/1, connect, and check the result.
        log("step 4: setting up client (validator stand-in) with permissive trust manager");
        X509TrustManager acceptAnyCert = new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                log("[client] checkServerTrusted() called -- accepting self-signed cert by design");
            }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        };

        SSLContext clientCtx = SSLContext.getInstance("TLS", "Mozilla-JSS");
        clientCtx.init(null, new TrustManager[] { acceptAnyCert }, null);

        JSSSocketFactory clientFactory = (JSSSocketFactory) clientCtx.getSocketFactory();
        JSSSocket clientSocket = (JSSSocket) clientFactory.createSocket();
        clientSocket.setApplicationProtocols(new String[] { ALPN_PROTOCOL });

        log("step 4: connecting to localhost:" + port);
        clientSocket.connect(new InetSocketAddress("localhost", port), 10_000);
        log("step 4: connected, starting handshake");
        clientSocket.startHandshake();
        log("step 4: handshake complete");

        try {
            String negotiated = clientSocket.getApplicationProtocol();
            log("step 5: negotiated protocol: [" + negotiated + "]");
            assert ALPN_PROTOCOL.equals(negotiated);

            java.security.cert.Certificate[] peerCerts = clientSocket.getSession().getPeerCertificates();
            log("step 5: received " + peerCerts.length + " peer certificate(s)");
            assert peerCerts.length == 1;
            X509Certificate presented = (X509Certificate) peerCerts[0];

            byte[] rawExtValue = presented.getExtensionValue(ACME_IDENTIFIER_OID_STRING);
            log("step 5: raw extension value present: " + (rawExtValue != null)
                + (rawExtValue != null ? (", length=" + rawExtValue.length) : ""));
            assert rawExtValue != null : "Challenge cert missing acmeIdentifier extension";

            // Unwrap twice: once for the standard X.509 extnValue OCTET
            // STRING, once more for RFC 8737's own OCTET STRING content.
            byte[] onceUnwrapped = X509ExtensionUtil.unwrapExtensionValue(rawExtValue);
            log("step 5: first unwrap -> " + onceUnwrapped.length + " bytes");
            byte[] actualDigest = X509ExtensionUtil.unwrapExtensionValue(onceUnwrapped);
            log("step 5: second unwrap -> " + actualDigest.length + " bytes (expect 32)");

            boolean digestMatches = MessageDigest.isEqual(actualDigest, expectedDigest);
            log("step 5: digest match: " + digestMatches);
            assert digestMatches : "acmeIdentifier digest mismatch";

            Collection<List<?>> sanEntries = presented.getSubjectAlternativeNames();
            log("step 6: SAN entries: " + sanEntries);
            assert sanEntries != null && sanEntries.size() == 1 : "Expected exactly one SAN entry";
            List<?> sanEntry = sanEntries.iterator().next();
            assert ((Integer) sanEntry.get(0)) == 2 : "Expected a dNSName SAN entry";
            assert hostname.equals(sanEntry.get(1)) : "SAN dNSName does not match expected hostname";
        } finally {
            log("step 7: closing client socket, waiting for server thread to finish");
            clientSocket.close();
            serverThread.join(5000);
        }

        if (serverError[0] != null) {
            log("=== FAILED: server thread reported an error ===");
            throw serverError[0];
        }

        log("=== PASSED ===");
    }

    public static void main(String[] args) throws Exception {
        // Args: nssdb, password [, hostname]
        TestSSLEngine.initialize(args);

        String hostname = args.length > 2 ? args[2] : "localhost";
        testSubscriberValidation(hostname);
    }
}
