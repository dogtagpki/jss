/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.tests;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.util.Date;
import java.util.Vector;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.ssl.SSLHandshakeCompletedEvent;
import org.mozilla.jss.ssl.SSLHandshakeCompletedListener;
import org.mozilla.jss.ssl.SSLSecurityStatus;
import org.mozilla.jss.ssl.SSLServerSocket;
import org.mozilla.jss.ssl.SSLSocket;
import org.mozilla.jss.util.PasswordCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JSS_FileUploadServer  {

    public static Logger logger = LoggerFactory.getLogger(JSS_FileUploadServer.class);

    private static Vector<String> jssSupportedCiphers = new Vector<>();
    private static SSLServerSocket serverSock = null;
    private static SSLSocket sock             = null;

    private String        fServerCertNick     = null;
    private String        fServerHost         = "localhost";
    private String        fPasswordFile       = "passwords";
    private String        fCertDbPath         = ".";
    private boolean       TestInetAddress     = false;
    private boolean       success             = true;
    public  static int    port                = 29755;
    public  static String usage               = "\nUSAGE:\njava "+
            "JSS_FileUploadServer "+
            "[certdb path] [password file]"+
            "\n[server_host_name] " +
            "[cert nickname]" +
            "[testInetAddress: true|false]";

    public static void main(String[] args) throws Exception {
        try {
            (new JSS_FileUploadServer()).doIt(args);
        } catch (Exception e) {
            System.out.println("Exception caught: " + e.getMessage());
            System.exit(1);
        }
        System.exit(0);
    }

    public void doIt(String[] args) throws Exception {

        if ( args.length < 1 || args[0].toLowerCase().indexOf("-h") != -1) {
            System.out.println(usage);
            System.exit(1);
        }

        int socketCntr = 0;
        try {
            if (args[0].length() > 0 &&
                    !args[0].equals("."))
                fCertDbPath = args[0];
            if (args[1].length() > 0 &&
                    !args[1].equals("passwords"))
                fPasswordFile = args[1];
            if (args[2].length() > 0 &&
                    !args[2].equals("localhost"))
                fServerHost = args[2];
            if (args[3].length() > 0)
                fServerCertNick = args[3];
        } catch (Exception e) {}

        CryptoManager    cm = CryptoManager.getInstance();
        CryptoToken     tok = cm.getInternalKeyStorageToken();
        PasswordCallback cb = new FilePasswordCallback(fPasswordFile);
        tok.login(cb);

        if (args[4].equalsIgnoreCase("true") == true) {
            TestInetAddress = true;
        }

        // We have to configure the server session ID cache before
        // creating any server sockets.
        SSLServerSocket.configServerSessionIDCache(10, 100, 100, null);
        //Disable SSL2
        SSLSocket.enableSSL2Default(false);
        //Note we will use the NSS default enabled ciphers suites

        // open the server socket and bind to the port
        logger.debug("Server about .... to create socket");

        if (TestInetAddress) {
            logger.debug("the HostName " + fServerHost +
                        " the Inet Address " +
                        InetAddress.getByName(fServerHost));
            serverSock = new SSLServerSocket(port, 5,
                    InetAddress.getByName(fServerHost), null , true);
        } else {
            logger.debug("Inet set to Null");
            serverSock = new SSLServerSocket(port, 5, null , null , true);
        }

        logger.debug("Server created socket");

        //serverSock.setSoTimeout(120 * 1000);
        serverSock.requireClientAuth(SSLSocket.SSL_REQUIRE_NO_ERROR);
        serverSock.setServerCertNickname(fServerCertNick);
        logger.debug("Server specified cert by nickname");

        System.out.println("Server ready to accept connections");
        while ( true ) {
            // accept the connection
            sock = (SSLSocket) serverSock.accept();
            //sock.setKeepAlive(true);
            sock.addHandshakeCompletedListener(
                    new HandshakeListener("server", this));
            socketCntr++;
            readWriteThread rwThread = new readWriteThread(sock, socketCntr);
            rwThread.start();
        }
    }

    /**
     * ReadWrite thread class that takes a
     * SSLSocket as input and sleeps
     * for 2 sec between sending some test
     * data and receiving.
     */
    private class readWriteThread extends Thread {
        private SSLSocket socket = null;
        private int socketCntr   = 0;

        public readWriteThread(SSLSocket sock, int cntr) {
            this.socket     = sock;
            this.socketCntr = cntr;
        }

        @Override
        public void run() {

            try {
                String socketData  = null;
                char[] cbuf        = null;
                int    readLength  = 0;
                String readString  = null;

                InputStream  is    = socket.getInputStream();
                BufferedReader in  = new BufferedReader(
                        new InputStreamReader(is));
                long timeInMs      = new Date().getTime();
                while ((readString = in.readLine()) != null) {
                    long now = new Date().getTime();
                    System.out.print("Read " + readString.getBytes().length +
                            "bytes in " + (now-timeInMs) + "\n");
                    timeInMs = now;
                }
            } catch (Exception e) {
                System.out.println("Exception caught in readWriteThread.run()\n");
                e.printStackTrace();
                System.exit(1);
            }
        }
    }

    public static class HandshakeListener
            implements SSLHandshakeCompletedListener {
        private String who;
        private JSS_FileUploadServer boss;
        public HandshakeListener(String who, JSS_FileUploadServer boss) {
            this.who = who;
            this.boss = boss;
        }
        @Override
        public void handshakeCompleted(SSLHandshakeCompletedEvent event) {
            try {
                String mesg = who + " got a completed handshake ";
                SSLSecurityStatus status = event.getStatus();
                if( status.isSecurityOn() ) {
                    mesg += "(security is ON)";
                } else {
                    mesg += "(security is OFF)";
                }
                logger.debug(mesg);
            } catch(Exception e) {
                logger.error(e.getMessage(), e);
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
