/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.tests;

import java.io.IOException;
import org.mozilla.jss.ssl.*;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.util.PasswordCallback;
import java.util.Vector;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import org.mozilla.jss.util.Debug;

/**************
 * Note on how to use JSS_SelfServServer and JSS_SelfServerClient
 *
 * For debugging purposes you should modify Constant.java debug_level to 4.
 *
 * First create db's and certificates
 * java -cp jss4.jar org.mozilla.jss.tests.SetupDBs . ./passwords
 * java -cp jss4.jar org.mozilla.jss.tests.GenerateTestCert . /passwords
 *                             localhost SHA-256/RSA CA_RSA Client_RSA Server_RSA
 *
 * Start the server:
 *
 *  java -cp ./jss4.jar org.mozilla.jss.tests.JSS_SelfServServer . passwords localhost 
 *             false 2921 verboseoff
 *
 * Start the client with 4 threads using ciphersuite 0x33.
 * Look at the file Constant.java for the ciphersuites values.
 *
 * java -cp jss4.jar org.mozilla.jss.tests.JSS_SelfServClient 2 0x33 
 * . localhost 2921 verboseoff JSS Client_RSA     
 *
 * If you envoke the client with a ciphersuite value -1
 * then all current JSS ciphersuites will be tested fox X number of
 * threads, and once all ciphersuites have been tested the client
 * will closed all client SSLSockets and then tell the server to
 * shutdown. This case is for the nightly automated tests.
 *
 * java -cp jss4.jar org.mozilla.jss.tests.JSS_SelfServClient 4 -1 
 * . passwords localhost 2921 verboseoff JSS
 */

public class JSS_SelfServServer  {
    
    private static Vector jssSupportedCiphers = new Vector();
    private static SSLServerSocket serverSock = null;
    private static SSLSocket sock             = null;
    
    public static void main(String[] args) throws Exception {
        try {
            (new JSS_SelfServServer()).doIt(args);
        } catch (Exception e) {
            System.out.println("JSS_SelfServServer exiting with Exception " + 
                    e.getMessage());
            System.exit(1);
        }
        System.exit(0);
    }
    
    private String        fServerCertNick = null;
    private String        fServerHost     = "localhost";
    private String        fPasswordFile   = "passwords";
    private String        fCertDbPath     = ".";
    private boolean       TestInetAddress = false;
    private boolean       success         = true;
    private boolean       bVerbose        = false;
    public  int    port            = 29754;
    public  static String usage           = "\nUSAGE:\njava JSS_SelfServServer"+
        " [certdb path] [password file]\n"+
        "[server_host_name] [testInetAddress: true|false]" +
        "<port> <verbose> <cert nickname> ";
    
    public void JSS_SelfServServer() {
        if (Constants.debug_level > 3) {
            bVerbose = true;
        }
    }
    
    public void doIt(String[] args) throws Exception {
        
        if ( args.length < 5  || args[0].toLowerCase().equals("-h")) {
            System.out.println(usage);
            System.exit(1);
        }
        try {
            if (!args[0].equals("."))
                fCertDbPath = args[0];
            if (!args[1].equals("passwords"))
                fPasswordFile = args[1];
            if (!args[2].equals("localhost"))
                fServerHost = args[2];
            if (args[3].equalsIgnoreCase("true") == true)
                TestInetAddress = true;
            if (args.length >= 5)
                port = new Integer(args[4]).intValue();
            if (args.length >=6 && args[5].equalsIgnoreCase("verbose")) {
                bVerbose = true;
            }
            if (args.length >=7 && !args[6].equalsIgnoreCase("default")) {
                fServerCertNick = args[6];
            }
        } catch (Exception e) {
            System.out.println("Error parsing command line " + e.getMessage());
            System.out.println(usage);
            System.exit(1);
        }
        
        if (bVerbose) System.out.println("initializing JSS");
        CryptoManager.initialize(fCertDbPath);
        CryptoManager    cm = CryptoManager.getInstance();
        CryptoToken     tok = cm.getInternalKeyStorageToken();
        PasswordCallback cb = new FilePasswordCallback(fPasswordFile);
        tok.login(cb);
        if (bVerbose) {
            Debug.setLevel(Debug.OBNOXIOUS);
        }
        // We have to configure the server session ID cache before
        // creating any server sockets.
        SSLServerSocket.configServerSessionIDCache(10, 100, 100, null);
        
        if (cm.FIPSEnabled()) {
            /* turn on only FIPS ciphersuites */
            /* Disable SSL2 and SSL3 ciphers */
            SSLSocket.enableSSL2Default(false);
            SSLSocket.enableSSL3Default(false);
            //Enable only FIPS ciphersuites.
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
        } else {
            /* turn on all implemented ciphersuites the server certificate
            * will determine if the ciphersuites can be used.
            */
            int ciphers[] =
                org.mozilla.jss.ssl.SSLSocket.getImplementedCipherSuites();
            for (int i = 0; i < ciphers.length;  ++i) {
                try {
                    SSLSocket.setCipherPreferenceDefault(ciphers[i], true);
                    if (bVerbose) {
                        System.out.println(Constants.cipher.cipherToString(
                            ciphers[i])  + " " +  
                            Integer.toHexString(ciphers[i]));
                    }
                } catch (Exception ex) {
                    ex.printStackTrace();
                    System.exit(1);
                }
            }
            //disable SSL2 ciphersuites
            SSLSocket.enableSSL2Default(false);
        }
        
        // open the server socket and bind to the port
        if (bVerbose)
            System.out.println("JSS_SelfServServ about .... to create socket");
        
        if (TestInetAddress) {
            if (bVerbose)
                System.out.println("JSS_SelfServServ HostName " + fServerHost +
                    " the Inet Address " +
                    InetAddress.getByName(fServerHost));
            serverSock = new SSLServerSocket(port, 5,
                InetAddress.getByName(fServerHost), null , true);
        } else {
            if (bVerbose)
                System.out.println("Inet set to Null");
            serverSock = new SSLServerSocket(port, 5, null , null , true);
        }
        
        if (bVerbose)
            System.out.println("JSS_SelfServServ created socket");
        
        serverSock.setSoTimeout(600*1000);  // Set timeout for 10 minutes
        serverSock.requireClientAuth(SSLSocket.SSL_REQUIRE_NO_ERROR);
        
        serverSock.setServerCertNickname("Server_ECDSA");
        serverSock.setServerCertNickname("Server_RSA");
        serverSock.setServerCertNickname("Server_DSS");
        
        if (bVerbose)
            System.out.println("JSS_SelfServServ specified cert by nickname");
        
        System.out.println("JSS_SelfServServ " + fServerHost +
            " ready to accept connections on " + port);
        int socketCntr = 0;
        try {
            while ( true ) {
                // accept the connection
                sock = (SSLSocket) serverSock.accept();
                sock.addHandshakeCompletedListener(
                    new HandshakeListener("server", this));

                socketCntr++;
                sock.setSoTimeout(300*1000);
                if (bVerbose) {
                    System.out.println("Timeout value for SSL sockets: " +
                        sock.getSoTimeout() + " milliseconds");
                }
                readWriteThread rwThread = new readWriteThread(sock, socketCntr);
                rwThread.start();
            }
        } catch (SocketTimeoutException ex) {
            
            if (socketCntr == 0) {
                System.out.println("JSS_SelfServServ No Client attempted to " +
                        "connect! If " +
                        "test ran from all.pl check the client execution " +
                        "for errors.");
            } else {
                System.out.println("JSS_SelfServServ there has been " + 
                        socketCntr + " client " +
                        " connections but the server Accept has timed out!");
            }
            System.out.println("JSS_SelfServServ Timeout value: " +
                        serverSock.getSoTimeout() + " milliseconds");
            ex.printStackTrace();
            System.out.println("JSS_SelfServServ exiting due to timeout.");
            System.exit(1);
        } catch (Exception ex) {
            System.out.println("JSS_SelfServServ Exception:");
            ex.printStackTrace();
            System.out.println("JSS_SelfServServ exiting.");
            System.exit(1);
        }
    }
    
    /**
     * ReadWrite thread class that takes a
     * SSLSocket as input and read then writes
     * back to client.
     */
    private class readWriteThread extends Thread {
        private SSLSocket socket = null;
        private int socketCntr   = 0;
        
        public readWriteThread(SSLSocket sock, int cntr) {
            this.socket     = sock;
            this.socketCntr = cntr;
        }
        
        public void run() {
            
            try {
                String inputLine   = null;
                String outputLine  = null;
                InputStream  is    = socket.getInputStream();
                OutputStream os    = socket.getOutputStream();
                BufferedReader bir = new BufferedReader(
                    new InputStreamReader(is));
                PrintWriter out    = new PrintWriter(new BufferedWriter(
                    new OutputStreamWriter(os)));
                
                while (true) {
                    
                    try {
                        if ((inputLine = bir.readLine()) != null) {
                            if (inputLine.equalsIgnoreCase("shutdown")) {
                                if (bVerbose) {
                                    System.out.println("Client told " +
                                        " JSS_SelfServServer to Shutdown!");
                                }
                                is.close();
                                os.close();
                                socket.close();
                                System.exit(0);
                            }
                            outputLine = "ServerSSLSocket- " + socketCntr;
                            
                            if (bVerbose) {
                                System.out.println("ServerSSLSocket-" +
                                    socketCntr + ": Received " + inputLine);
                                System.out.println("Sending" + outputLine);
                            }
                            out.println(outputLine);
                            out.flush();
                        } else {
                                 /* if you read null then quit. otherwise you
                                  * will be in endless loop with the socket
                                  * stuck in CLOSED_WAIT.
                                  */
                            if (bVerbose) {
                                System.out.println("ServerSSLSocket-" +
                                    socketCntr +
                                    " read null aborting connection.");
                            }
                            break;
                        }
                        
                    } catch (SocketTimeoutException ste) {
                        System.out.println("ServerSSLSocket-" + socketCntr +
                            " timed out: " +  ste.toString());
                        break;
                    } catch (IOException ex) {
                        break;
                    }
                }
                
                /* close streams and close socket */
                is.close();
                os.close();
                socket.close();
                if (bVerbose) {
                    System.out.println("ServerSSLSocket " + socketCntr +
                        " has been Closed.");
                }
            } catch (IOException e) {
                
                e.printStackTrace();
            }
            
        }
    }
    
    public static class HandshakeListener
        implements SSLHandshakeCompletedListener {
        private String who;
        private JSS_SelfServServer boss;
        public HandshakeListener(String who, JSS_SelfServServer boss) {
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
                if (Constants.debug_level > 3) System.out.println(mesg);
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
}
