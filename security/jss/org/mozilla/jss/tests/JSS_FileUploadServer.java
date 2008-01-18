/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is Netscape Security Services for Java.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 2002
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

package org.mozilla.jss.tests;

import org.mozilla.jss.ssl.*;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.ssl.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.pkix.primitive.*;
import org.mozilla.jss.pkix.cert.*;
import org.mozilla.jss.pkix.cert.Certificate;
import org.mozilla.jss.util.PasswordCallback;

import org.mozilla.jss.tests.*;

import java.util.Calendar;
import java.util.Date;
import java.util.Vector;
import java.security.*;
import java.security.PrivateKey;
import java.net.InetAddress;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.EOFException;
import java.io.InputStreamReader;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.FileReader;

public class JSS_FileUploadServer  {
    
    private static Vector jssSupportedCiphers = new Vector();
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
        
        CryptoManager.initialize(fCertDbPath);
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
        if ( Constants.debug_level >= 3 )
            System.out.println("Server about .... to create socket");
        
        if (TestInetAddress) {
            if ( Constants.debug_level >= 3 )
                System.out.println("the HostName " + fServerHost +
                        " the Inet Address " +
                        InetAddress.getByName(fServerHost));
            serverSock = new SSLServerSocket(port, 5,
                    InetAddress.getByName(fServerHost), null , true);
        } else {
            if ( Constants.debug_level >= 3 )
                System.out.println("Inet set to Null");
            serverSock = new SSLServerSocket(port, 5, null , null , true);
        }
        
        if ( Constants.debug_level >= 3 )
            System.out.println("Server created socket");
        
        //serverSock.setSoTimeout(120 * 1000);
        serverSock.requireClientAuth(SSLSocket.SSL_REQUIRE_NO_ERROR);
        serverSock.setServerCertNickname(fServerCertNick);
        if ( Constants.debug_level >= 3 )
            System.out.println("Server specified cert by nickname");
        
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
        }
    }
    
    public synchronized void setFailure() {
        success = false;
    }
    
    public synchronized boolean getSuccess() {
        return success;
    }
}
