/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.tests;

import java.security.cert.CertificateEncodingException;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.ssl.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.pkix.primitive.*;
import org.mozilla.jss.pkix.cert.*;
import org.mozilla.jss.pkix.cert.Certificate;
import org.mozilla.jss.util.PasswordCallback;
import java.util.Calendar;
import java.util.Date;
import java.security.*;
import java.security.PrivateKey;
import java.io.*;
import java.net.SocketException;

/**
 * SSLClientAuth Server/client test.
 */
public class SSLClientAuth implements Runnable {
    
    private CryptoManager cm;
    public static final SignatureAlgorithm sigAlg =
            SignatureAlgorithm.RSASignatureWithSHA1Digest;
    
    /**
     * Method that generates a certificate for given credential
     *
     * @param issuerName
     * @param subjectName
     * @param serialNumber
     * @param privKey
     * @param pubKey
     * @param rand
     * @param extensions
     * @throws java.lang.Exception
     * @return Certificate
     */
    public static Certificate makeCert(String issuerName, String subjectName,
            int serialNumber, PrivateKey privKey, PublicKey pubKey, int rand,
            SEQUENCE extensions) throws Exception {
        AlgorithmIdentifier sigAlgID = new AlgorithmIdentifier( sigAlg.toOID());
        
        Name issuer = new Name();
        issuer.addCountryName("US");
        issuer.addOrganizationName("Mozilla");
        issuer.addOrganizationalUnitName("JSS Testing" + rand);
        issuer.addCommonName(issuerName);
        
        Name subject = new Name();
        subject.addCountryName("US");
        subject.addOrganizationName("Mozilla");
        subject.addOrganizationalUnitName("JSS Testing" + rand);
        subject.addCommonName(subjectName);
        
        Calendar cal = Calendar.getInstance();
        Date notBefore = cal.getTime();
        cal.add(Calendar.YEAR, 1);
        Date notAfter = cal.getTime();
        
        SubjectPublicKeyInfo.Template spkiTemp =
                new SubjectPublicKeyInfo.Template();
        SubjectPublicKeyInfo spki =
                (SubjectPublicKeyInfo) ASN1Util.decode(spkiTemp,
                pubKey.getEncoded());
        
        CertificateInfo info = new CertificateInfo(
                CertificateInfo.v3, new INTEGER(serialNumber), sigAlgID,
                issuer, notBefore, notAfter, subject, spki);
        if( extensions != null ) {
            info.setExtensions(extensions);
        }
        
        return new Certificate(info, privKey, sigAlg);
    }
    
    /**
     *
     * @param args
     * @throws java.lang.Exception
     */
    public static void main(String[] args) throws Exception {
        (new SSLClientAuth()).doIt(args);
    }
    
    private X509Certificate nssServerCert, nssClientCert;
    private String serverCertNick, clientCertNick;
    
    
    /**
     *
     * @param args
     * @throws java.lang.Exception
     */
    public void doIt(String[] args) throws Exception {
        
        if ( args.length < 2 ) {
            System.out.println("Usage: java org.mozilla.jss.tests." +
                    "SSLClientAuth <dbdir> <passwordFile> [port]" +
                    " [Certificate Serial Number]");
            System.exit(1);
        }
        
        CryptoManager.initialize(args[0]);
        cm = CryptoManager.getInstance();
        CryptoToken tok = cm.getInternalKeyStorageToken();
        
        PasswordCallback cb = new FilePasswordCallback(args[1]);
        tok.login(cb);
        
        if (args.length >= 3) {
            port = new Integer(args[2]).intValue();
            System.out.println("using port:" + port);
        }
        
        if (args.length >= 4) {
            serialNum = new Integer(args[3]).intValue();
        } else {
             SecureRandom rng= SecureRandom.getInstance("pkcs11prng",
                "Mozilla-JSS");
             serialNum = nextRandInt(rng);
        }
        X509Certificate[] certs;
        /* ensure certificate does not already exists */
        /* we don't have to test all three */
        serverCertNick = "SSLserver-"+serialNum;
        clientCertNick = "SSLclient-"+serialNum;
        
        certs = cm.findCertsByNickname(serverCertNick);
        if (certs.length == 0) {
            generateCerts(cm, serialNum);
        } else {
            try {
                nssServerCert = cm.findCertByNickname(serverCertNick);
                nssClientCert = cm.findCertByNickname(clientCertNick);
            } catch (TokenException ex) {
                ex.printStackTrace();
                System.exit(1);
            } catch (ObjectNotFoundException ex) {
                ex.printStackTrace();
                System.exit(1);
            }
            
        }
        configureDefaultSSLoptions();
        
        useNickname = false;
        testConnection();
        useNickname = true;
        testConnection();
        
        System.out.println("Exiting main()");
        if( getSuccess() ) {
            System.exit(0);
        } else {
            System.exit(1);
        }
    }
    
    private boolean useNickname;
    
    private void generateCerts(CryptoManager cm, int serialNum) {
        
        // RSA Key with default exponent
        int keyLength = 1024;
        try {
            java.security.KeyPairGenerator kpg =
                    java.security.KeyPairGenerator.getInstance("RSA",
                    "Mozilla-JSS");
            kpg.initialize(keyLength);
            KeyPair caPair = kpg.genKeyPair();
            //Generate CA cert
            SEQUENCE extensions = new SEQUENCE();
            extensions.addElement(makeBasicConstraintsExtension());
            Certificate caCert = makeCert("CACert", "CACert", serialNum,
                    caPair.getPrivate(), caPair.getPublic(), serialNum, extensions);
            X509Certificate nssCaCert = cm.importUserCACertPackage(
                    ASN1Util.encode(caCert), "SSLCA-"+serialNum);
            InternalCertificate intern = (InternalCertificate)nssCaCert;
            intern.setSSLTrust(
                    InternalCertificate.TRUSTED_CA |
                    InternalCertificate.TRUSTED_CLIENT_CA |
                    InternalCertificate.VALID_CA);
            
            // generate server cert
            kpg.initialize(keyLength);
            KeyPair serverPair = kpg.genKeyPair();
            Certificate serverCert = makeCert("CACert", "localhost",
                    serialNum+1, caPair.getPrivate(), serverPair.getPublic(),
                    serialNum, null);
            nssServerCert = cm.importCertPackage(
                    ASN1Util.encode(serverCert), serverCertNick);
            
            // generate client auth cert
            kpg.initialize(keyLength);
            KeyPair clientPair = kpg.genKeyPair();
            Certificate clientCert = makeCert("CACert", "ClientCert",
                    serialNum+2, caPair.getPrivate(), clientPair.getPublic(),
                    serialNum, null);
            nssClientCert = cm.importCertPackage(
                    ASN1Util.encode(clientCert), clientCertNick);
        } catch (CertificateEncodingException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (NoSuchProviderException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (CryptoManager.NicknameConflictException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (CryptoManager.UserCertConflictException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (TokenException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (NoSuchItemOnTokenException ex) {
            ex.printStackTrace();
            System.exit(1);
        } catch (Exception ex) {
            ex.printStackTrace();
            System.exit(1);
        }
        
    }
    private void configureDefaultSSLoptions() {
        try {
            //Disable SSL2 and SSL3 ciphers
            SSLSocket.enableSSL2Default(false);
            SSLSocket.enableSSL3Default(false);
            /* TLS is enabled by default */

            /* Enable Session tickets by default */
            SSLSocket.enableSessionTicketsDefault(true);

            /* if FIPS is enabled, configure only FIPS ciphersuites */
            if (cm.FIPSEnabled()) {
                System.out.println("The NSS database is configured in FIPS" +
                        "mode.");
                System.out.println("Enable ony FIPS ciphersuites.");
                int ciphers[] =
                        org.mozilla.jss.ssl.SSLSocket.getImplementedCipherSuites();
                for (int i = 0; i < ciphers.length;  ++i) {
                    if (SSLSocket.isFipsCipherSuite(ciphers[i])) {
                        /* enable the FIPS ciphersuite */
                        SSLSocket.setCipherPreferenceDefault(ciphers[i], true);
                    } else if (SSLSocket.getCipherPreferenceDefault(
                            ciphers[i])) {
                        /* disable the non fips ciphersuite */
                        SSLSocket.setCipherPreferenceDefault(ciphers[i], false);
                    }
                }
            }
        } catch (SocketException ex) {
            System.out.println("Error configuring default SSL options.");
            ex.printStackTrace();
            System.exit(1);
        }
    }
    
    private void testConnection() throws Exception {
        serverReady = false;
        
        // spawn server
        Thread server = new Thread(this);
        server.start();
        
        // wait for server to open its socket
        synchronized(this) {
            while(!serverReady) {
                this.wait();
            }
        }
        
        // connect to the server
        System.out.println("client about to connect");
        SSLSocket sock = new SSLSocket("localhost", port);
        if( useNickname ) {
            sock.setClientCertNickname(clientCertNick);
            System.out.println("Client specified cert by nickname");
        } else {
            sock.setClientCert(nssClientCert);
            System.out.println("Client specified cert directly");
        }
        System.out.println("client connected");
        sock.addHandshakeCompletedListener(
                new HandshakeListener("client",this));
        
        // force the handshake
        sock.forceHandshake();
        String cipher = sock.getStatus().getCipher();
        System.out.println("client forced handshake. ciphersuite: " + cipher);
        sock.close();
        
        // wait for the server to finish
        server.join();
    }
    
    public static class HandshakeListener
            implements SSLHandshakeCompletedListener {
        private String who;
        private SSLClientAuth boss;
        public HandshakeListener(String who, SSLClientAuth boss) {
            this.who = who;
            this.boss = boss;
        }
        public void handshakeCompleted(SSLHandshakeCompletedEvent event) {
            try {
                String mesg = who + " got a completed handshake ";
                SSLSecurityStatus status = event.getStatus();
                if( status.isSecurityOn() ) {
                    mesg += "(security is ON)";
                } else {
                    mesg += "(security is OFF)";
                }
                System.out.println(mesg);
            } catch(Exception e) {
                e.printStackTrace();
                boss.setFailure();
            }
        }
    }
    
    public synchronized void setFailure() {
        success = false;
    }
    
    public synchronized boolean getSuccess() {
        return success;
    }
    
    private boolean success = true;
    
    public int port = 29752;
    public int serialNum = 0;
    
    public boolean serverReady = false;
    
    /**
     * Server run method.
     */
    public void run() {
        try {
            
            // We have to configure the server session ID cache before
            // creating any server sockets.
            SSLServerSocket.configServerSessionIDCache(10, 100, 100, null);
            
            // open the server socket and bind to the port
            System.out.println("Server about to create socket");
            SSLServerSocket serverSock = new SSLServerSocket(port, 5, null, null,
                    true);
            System.out.println("Server created socket");
            serverSock.requireClientAuth(SSLSocket.SSL_REQUIRE_NO_ERROR);
            if( useNickname ) {
                serverSock.setServerCertNickname(serverCertNick);
                System.out.println("Server specified cert by nickname");
            } else {
                serverSock.setServerCert(nssServerCert);
                System.out.println("Server specified cert directly");
            }
            
            // tell the client we're ready
            synchronized(this) {
                serverReady = true;
                this.notify();
            }
            
            // accept the connection
            System.out.println("Server about to accept");
            SSLSocket sock = (SSLSocket) serverSock.accept();
            System.out.println("Server accepted");
            sock.addHandshakeCompletedListener(
                    new HandshakeListener("server", this));
            
            // try to read some bytes, to allow the handshake to go through
            InputStream is = sock.getInputStream();
            try {
                System.out.println("Server about to read");
                is.read();
                System.out.println("Server read successful");
            } catch(EOFException e) {
                System.out.println("Server got EOF");
            }
            sock.close();
            serverSock.close();
            
        } catch(Exception e) {
            synchronized(this) {
                serverReady = true;
                setFailure();
                this.notify();
            }
            e.printStackTrace();
        }
        System.out.println("Server exiting");
    }
    
    static Extension makeBasicConstraintsExtension() throws Exception {
        SEQUENCE bc = new SEQUENCE();
        bc.addElement( new BOOLEAN(true) ); // cA
        OBJECT_IDENTIFIER bcOID = new OBJECT_IDENTIFIER(
                new long[] {2, 5, 29, 19}); // from RFC 2459
        OCTET_STRING enc = new OCTET_STRING(ASN1Util.encode(bc));
        return new Extension(bcOID, true, enc);
    }
    
    static int nextRandInt(SecureRandom rand) throws Exception {
        int i;
        byte[] bytes = new byte[4];
        rand.nextBytes(bytes);
        i =  ((int)bytes[0])<<24 | ((int)bytes[1])<<16 |
                ((int)bytes[2])<<8 | ((int)bytes[3]);
        System.out.println("generated random value:" + i);
        return i;
    }
    
}
