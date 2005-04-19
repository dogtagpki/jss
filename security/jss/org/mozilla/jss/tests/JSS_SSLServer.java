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
import java.io.InputStreamReader;
import java.io.InputStream;
import java.io.EOFException;
import java.io.IOException;

public class JSS_SSLServer  {
    
    private static Vector jssSupportedCiphers = new Vector();
    private static SSLServerSocket serverSock = null;
    private static SSLSocket sock             = null;
    
    public static void main(String[] args) throws Exception {
        try {
            (new JSS_SSLServer()).doIt(args);
        } catch (Exception e) {}
        
        // Put the main thread to sleep.  In case we do not get any
        // response within 120 sec (2 min), then we shutdown the server.
        try {
            Thread.currentThread().sleep(12000);
            sock.close();
            serverSock.close();
        } catch (InterruptedException e) {
            System.out.println("Thread Interrupted, exiting normally ...\n");
            System.exit(0);
        } catch (Exception ex) {
        }
    }
    
    private String        serverCertNick  = null;
    private String        serverHost      = null;
    private boolean       TestInetAddress = false;
    private boolean       success         = true;
    public  static int    port            = 29750;
    public  static String usage           = "USAGE: java JSS_SSLServer . " +
            "passwords server_name " +
            "servercertnick [ true | false ]";
    
    public void doIt(String[] args) throws Exception {
        
        if ( args.length < 1 ) {
            System.out.println(usage);
            System.exit(0);
        }
        
        CryptoManager.initialize(args[0]);
        CryptoManager    cm = CryptoManager.getInstance();
        CryptoToken     tok = cm.getInternalKeyStorageToken();
        PasswordCallback cb = new FilePasswordCallback(args[1]); // passwords
        tok.login(cb);
        serverHost          = args[2]; // localhost
        serverCertNick      = args[3]; // servercertnick
        
        if (args[4].equalsIgnoreCase("true") == true) {
            TestInetAddress = true;
        }
        
        // We have to configure the server session ID cache before
        // creating any server sockets.
        SSLServerSocket.configServerSessionIDCache(10, 100, 100, null);
        
        /* enable all the SSL2 cipher suites  */
        for (int i = SSLSocket.SSL2_RC4_128_WITH_MD5;
        i <= SSLSocket.SSL2_DES_192_EDE3_CBC_WITH_MD5; ++i) {
            if (i != SSLSocket.SSL2_IDEA_128_CBC_WITH_MD5) {
                SSLSocket.setCipherPreferenceDefault( i, true);
            }
        }
        
        /* enable all the SSL3 and TLS cipher suites */
        for (int i = 0; Constants.jssCipherSuites[i] != 0;  ++i) {
            try {
                SSLSocket.setCipherPreferenceDefault(
                        Constants.jssCipherSuites[i], true);
            } catch (Exception ex) {
            }
        }
        
        // open the server socket and bind to the port
        if ( Constants.debug_level >= 3 )
            System.out.println("Server about .... to create socket");
        
        if (TestInetAddress) {
            if ( Constants.debug_level >= 3 )
                System.out.println("the HostName " + serverHost +
                        " the Inet Address " +
                        InetAddress.getByName(serverHost));
            serverSock = new SSLServerSocket(port, 5,
                    InetAddress.getByName(serverHost), null , true);
        } else {
            if ( Constants.debug_level >= 3 )
                System.out.println("Inet set to Null");
            serverSock = new SSLServerSocket(port, 5, null , null , true);
        }
        
        if ( Constants.debug_level >= 3 )
            System.out.println("Server created socket");
        
        serverSock.setSoTimeout(120 * 1000);
        serverSock.requireClientAuth(true, true);
        serverSock.setServerCertNickname(serverCertNick);
        if ( Constants.debug_level >= 3 )
            System.out.println("Server specified cert by nickname");
        
        boolean socketListenStatus = true;
        
        while ( socketListenStatus ) {
            // accept the connection
            sock = (SSLSocket) serverSock.accept();
            sock.addHandshakeCompletedListener(
                    new HandshakeListener("server", this));
            
            // try to read some bytes, to allow the handshake to go through
            InputStream is = sock.getInputStream();
            try {
                BufferedReader bir = new BufferedReader(
                        new InputStreamReader(is));
                String socketData  = bir.readLine();
                if ( socketData.equals("null") )
                    socketListenStatus = false;
                else if ( socketData != null )
                    jssSupportedCiphers.add(socketData);
            } catch(EOFException e) {
            } catch(IOException ex) {
            } catch(NullPointerException npe) {
                socketListenStatus = false;
            }
            sock.close();
        }
        
        serverSock.close();
        
        System.out.println("Server exiting");
        System.out.println("-----------------------------------------" +
                "----------------");
        System.out.println("Summary of JSSE client to JSS server " +
                "communication test :");
        System.out.println("-----------------------------------------" +
                "----------------");
        for ( int i=0; i<jssSupportedCiphers.size(); i++ ) {
            System.out.println("["+i+"]\t"+jssSupportedCiphers.elementAt(i));
        }
        System.out.println("-----------------------------------------" +
                "----------------");
        System.out.println("Please note that in JDK 5.0 the same set of ");
        System.out.println("ciphers are exercised for SSLv3 and TLS.");
        System.out.println("-----------------------------------------" +
                "----------------");
        System.out.flush();
        
        
        if( getSuccess() ) {
            System.exit(0);
        } else {
            System.exit(1);
        }
    }
    
    public static class HandshakeListener
            implements SSLHandshakeCompletedListener {
        private String who;
        private JSS_SSLServer boss;
        public HandshakeListener(String who, JSS_SSLServer boss) {
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
