/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.tests;

import java.io.*;
import java.net.*;
import java.util.Vector;
import javax.net.*;

/*
 * ClassServer.java -- JSSE_SSLServer implements this
 * class.
 */
public abstract class ClassServer implements Runnable {
    
    private ServerSocket server             = null;
    private Vector       supportedCiphers   = new Vector();
    
    /**
     * Constructs a ClassServer based on <b>ss</b>
     */
    protected ClassServer(ServerSocket ss) {
        server = ss;
        newListener();
    }
    
    /**
     * The "listen" thread that accepts a connection to the
     * server, parses the header to obtain the file name
     * and sends back the bytes for the file (or error
     * if the file is not found or the response was malformed).
     */
    public void run() {
        Socket  socket             = null;
        boolean socketListenStatus = true;
        
        // accept a connection
        while ( socketListenStatus ) {
            try {
                socket = server.accept();
            } catch (Exception ex) {
                System.exit(1);
            }
            
            newListener();
            
            //try to read some bytes, to allow the handshake to go through
            try {
                InputStream is     = socket.getInputStream();
                BufferedReader bir = new BufferedReader(
                        new InputStreamReader(is));
                String socketData  = bir.readLine();
                if ( socketData.equals("null") )
                    socketListenStatus = false;
                else if ( socketData != null )
                    supportedCiphers.add(socketData);
                socket.close();
            } catch(EOFException e) {
            } catch(IOException ex) {
            } catch(NullPointerException npe) {
                socketListenStatus = false;
            }
        }
        
        try {
            server.close();
        } catch (Exception ex) {
            System.exit(1);
        }
        
        System.out.println("Server exiting");
        System.out.println("-------------------------------------------" +
                           "-------------");
        System.out.println("Summary of JSS client to JSSE server " +
                           "communication test :");
        System.out.println("-------------------------------------------" +
                           "-------------");
        System.out.println("supportedCiphers.size " + supportedCiphers.size());
        System.out.println("Constants.jssCiphersSuites "+  
                            Constants.jssCipherSuites.length);
        
        for ( int i=0; i<(supportedCiphers.size()-1); i++ ) {
            System.out.print(i + " SC " +
            new Integer((String)supportedCiphers.elementAt(i)).intValue()); 
            
            for ( int j=0; j<(Constants.jssCipherSuites.length); j++ ) {
               if (new Integer((String)supportedCiphers.elementAt(i)).intValue() 
                   == Constants.jssCipherSuites[j].value ) {
                    System.out.print(" JSSC ");
                    System.out.println(" ["+ i +"]\t" + 
                                       Constants.jssCipherSuites[j].name);
                    System.out.flush();
                }
            } 
        }
        System.out.println("-------------------------------------------" +
                           "-------------");
        System.out.flush();
        
        if( !socketListenStatus ) {
            System.exit(0);
        }
    }
    
    /**
     * Create a new thread to listen.
     */
    private void newListener() {
        (new Thread(this)).start();
    }
}
