/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.tests;

import org.mozilla.jss.ssl.*;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.pkix.primitive.*;
import org.mozilla.jss.pkix.cert.*;
import org.mozilla.jss.util.PasswordCallback;

import java.security.*;
import java.net.*;
import java.io.*;

public class JSS_FileUploadClient {

    private String  clientCertNick      = null;
    private String  serverHost          = null;
    private boolean TestCertCallBack    = false;
    private boolean success             = true;
    private int     fCipher             = -1;
    private int     port                = 29755;
    private String  EOF                 = "test";
    private boolean handshakeCompleted  = false;
    
    private CryptoManager    cm          = null;
    private CryptoToken      tok         = null;
    private PasswordCallback cb          = null;
    private String  fPasswordFile        = "passwords";
    private String  fCertDbPath          = ".";
    private String  fUploadFile          = "foo.in";
    
    /**
     * Default Constructor, do not use.
     */
    public JSS_FileUploadClient() {
    }
    
    /**
     * Initialize the desired cipher to be set
     * on the socket.
     * @param aCipher
     */
    public void setCipher(int aCipher) {
        fCipher = aCipher;
    }
    
    /**
     * Initialize the hostname to run the server
     * @param aHostName
     */
    public void setHostName(String aHostName) {
        serverHost = aHostName;
    }
    
    /**
     * Initialize the port to run the server
     * @param aPort
     */
    public void setPort(int aPort) {
        port = aPort;
    }
    
    /**
     * Initialize the passwords file name
     * @param aPasswordFile
     */
    public void setPasswordFile(String aPasswordFile) {
        fPasswordFile = aPasswordFile;
    }
    
    /**
     * Initialize the cert db path name
     * @param aCertDbPath
     */
    public void setCertDbPath(String aCertDbPath) {
        fCertDbPath = aCertDbPath;
    }
    
    /**
     * Initialize the name of the file to
     * be used for testing along with full path.
     * @param aUploadFile
     */
    public void setUploadFile(String aUploadFile) {
        fUploadFile = aUploadFile;
    }
    
    /**
     * Enable/disable Test Cert Callback.
     * @param aTestCertCallback
     */
    public void setTestCertCallback(boolean aTestCertCallback) {
        TestCertCallBack = aTestCertCallback;
    }
    
    /**
     * Set client certificate
     * @param aClientCertNick Certificate Nick Name
     */
    public void setClientCertNick(String aClientCertNick) {
        clientCertNick = aClientCertNick;
    }
    
    /**
     * Return true if handshake is completed
     * else return false;
     * @return boolean handshake status
     */
    public boolean isHandshakeCompleted() {
        return this.handshakeCompleted;
    }

    /**
     * Set handshakeCompleted flag to indicate
     * that the socket handshake is coplete.
     */
    public void setHandshakeCompleted() {
        this.handshakeCompleted = true;
    }

    /**
     * Clear handshakeCompleted flag to indicate
     * that the system is now ready for another
     * socket connection.
     */
    public void clearHandshakeCompleted() {
        this.handshakeCompleted = false;
    }
    
    /**
     * Set EOF for closing server socket
     * @param fEof null for closing server socket
     */
    public void setEOF(String fEof) {
        this.EOF = fEof;
    }
    
    /**
     * ReadWrite thread class that takes a
     * SSLSocket as input and sleeps
     * for 2 sec between sending some test
     * data and receiving.
     * NOTE: If bufferedStream.mark(Integer.MAX_VALUE);
     * method is invoked then fill method of 
     * BufferedInputStream class copies lot of data using 
     * System.arraycopy (which in-turn use memcpy). This 
     * causes very high CPU usage.
     */
    private class readWriteThread extends Thread {
        private SSLSocket clientSock = null;
        private int socketCntr   = 0;
        
        public readWriteThread(SSLSocket sock, int cntr) {
            clientSock = sock;
            socketCntr = cntr;
        }
        
        public void run() {
            
            try {
                String socketData  = null;
                char[] cbuf        = null;
                int    readLength  = 0;
                String readString  = null;
                
                OutputStream   os  = clientSock.getOutputStream();
                System.out.println("Reading file foo.in");
                BufferedReader in  = new BufferedReader(
                        new FileReader(fUploadFile));
                System.out.println("Successfully got a handle to " +
                                    fUploadFile);
                PrintWriter   out  = new PrintWriter(new BufferedWriter(
                        new OutputStreamWriter(os)));

                while ((readString = in.readLine()) != null) {
                    System.out.println("Read:" + readString);
                    out.println(readString);
                    out.flush();
                }
                in.close();
                out.close();
            } catch (Exception e) {
                System.out.println("Exception caught" + e.getMessage());
                e.printStackTrace();
                System.exit(1);
            }
        }
    }

    /**
     * Initialize and create a socket connection to
     * SSLServer using the set parameters.
     */
    public void doIt() throws Exception {

        try {
            CryptoManager.initialize(fCertDbPath);
            cm  = CryptoManager.getInstance();
            tok = cm.getInternalKeyStorageToken();
            cb  = new FilePasswordCallback(fPasswordFile);
            tok.login(cb);
        } catch (Exception e) {
        }

        // connect to the server
        if ( Constants.debug_level >= 3 )
            System.out.println("client about to connect...");

        String hostAddr =
                InetAddress.getByName(serverHost).getHostAddress();

        if ( Constants.debug_level >= 3 )
            System.out.println("the host " + serverHost +
                    " and the address " + hostAddr);

        SSLCertificateApprovalCallback approvalCallback =
                new TestCertApprovalCallback();
        SSLClientCertificateSelectionCallback certSelectionCallback =
                new TestClientCertificateSelectionCallback();

        SSLSocket sock = null;

        if (TestCertCallBack) {
            if ( Constants.debug_level >= 3 )
                System.out.println("calling approvalCallBack");
            sock = new SSLSocket(InetAddress.getByName(hostAddr),
                    port,
                    null,
                    0,
                    new TestCertApprovalCallback(),
                    null);
        } else {
            if ( Constants.debug_level >= 3 )
                System.out.println("NOT calling approvalCallBack");
            sock = new SSLSocket(InetAddress.getByName(hostAddr),
                    port);
        }

        if ( Constants.debug_level >= 3 )
            System.out.println("clientCertNick=" + clientCertNick);
        sock.setClientCertNickname(clientCertNick);
        if ( fCipher != -1 ) {
            sock.setCipherPreference(fCipher, true);
        }
        if ( Constants.debug_level >= 3 ) {
            System.out.println("Client specified cert by nickname");
            System.out.println("client connected");
        }

        // Set socket timeout to 10 sec
        //sock.setSoTimeout(10 * 1000);
        //sock.setKeepAlive(true);
        sock.addHandshakeCompletedListener(
                new HandshakeListener("client",this));
        sock.forceHandshake();
        readWriteThread rwThread = new readWriteThread(sock, 0);
        rwThread.start();
    }

    /**
     * SSL Handshake Listener implementation.
     */
    public class HandshakeListener
            implements SSLHandshakeCompletedListener {
        private String who;
        private JSS_FileUploadClient boss;
        public HandshakeListener(String who, JSS_FileUploadClient boss) {
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
                if ( Constants.debug_level >= 3 )
                    System.out.println(mesg);
            } catch(Exception e) {
                e.printStackTrace();
                boss.setFailure();
            }
            setHandshakeCompleted();
        }
    }

    /**
     * Set status return value to false.
     */
    public synchronized void setFailure() {
        success = false;
    }

    /**
     * Set status return value to success.
     */
    public synchronized boolean getSuccess() {
        return success;
    }

    /**
     * Main method. Used for unit testing.
     */
    public static void main(String[] args) {

        String  certnick   = "JSSCATestCert";
        String  testCipher = "1";
        String  testhost   = "localhost";
        int     testport   = 29755;
        int     socketCntr = 1;
        String  certDbPath = null;
        String  passwdFile = null;
        String  uploadFile = "foo.in";

        String  usage      = "\nUSAGE:\n" +
                "java org.mozilla.jss.tests.JSS_FileUploadClient" +
                " [# sockets] [JSS cipher integer]\n[certdb path]" +
                " [password file] [upload test file] " +
                " [server host] [server port]";

        try {
            if (args.length <= 0 || args[0].toLowerCase().equals("-h")) {
                System.out.println(usage);
                System.exit(1);
            } else {
                socketCntr = new Integer(args[0]).intValue();
                System.out.println("Socket Counter = " + socketCntr);
            }
            testCipher = (String)args[1];
            System.out.println("Test Cipher    = " + testCipher);

            if ( args.length >= 3 ) {
                certDbPath = (String)args[2];
                passwdFile = (String)args[3];
            }

            if ( args.length >= 5 ) {
                uploadFile = (String)args[4];
                testhost   = (String)args[5];
                testport   = new Integer(args[6]).intValue();
            }
        } catch (Exception e) { }

        System.out.println("Client connecting to server ...");

        for ( int j=0; j<socketCntr; j++) {
            JSS_FileUploadClient jssTest = new JSS_FileUploadClient();
            try {
                if ( !testhost.equals("localhost") )
                    jssTest.setHostName(testhost);

                if ( testport != 29755 )
                    jssTest.setPort(testport);

                jssTest.setTestCertCallback(true);
                jssTest.setClientCertNick(certnick);

                if ( certDbPath != null )
                    jssTest.setCertDbPath(certDbPath);

                if ( passwdFile != null )
                    jssTest.setPasswordFile(passwdFile);

                if ( !uploadFile.equals("foo.in") )
                    jssTest.setUploadFile(uploadFile);

                if ( testCipher != null ) {
                    try {
                        jssTest.setCipher(new Integer(testCipher).intValue());
                        jssTest.setEOF(testCipher);
                        jssTest.doIt();
                    } catch (Exception ex) {
                        System.out.println(ex.getMessage());
                        ex.printStackTrace();
                        System.exit(1);
                    }
                }
            } catch (Exception ex) {
                System.out.println(ex.getMessage());
                ex.printStackTrace();
                System.exit(1);
            }
        }
        System.out.println("All " + socketCntr + " sockets created. Exiting");
        // Sleep for 5 min
        try {
            Thread.sleep(300*1000);
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
            System.exit(1);
        }
        System.exit(0);
    }
}
