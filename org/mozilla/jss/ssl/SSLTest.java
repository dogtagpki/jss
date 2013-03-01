/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.ssl;

import java.net.*;
import java.io.*;
import org.mozilla.jss.CryptoManager;
import java.util.*;

public class SSLTest {

    public static void main(String[] args) {
        new SSLTest(args);
    }

    private Hashtable params = new Hashtable();

    private String[] defaults = {
        "port", "443",
        "host", "www.amazon.com",
        "remotehost", "www.amazon.com"
    };

    private void initParams() {
        processArgs(defaults);
    }

    private void processArgs(String[] args) {
        int i;

        for(i=0; i < args.length; i+=2) {
            System.out.flush();
            params.put(args[i], args[i+1]);
        }
    }

    private void dumpParams() {
        Enumeration _enum = params.keys();
        System.out.println("Parameters:");
        while (_enum.hasMoreElements() ) {
            String key = (String) _enum.nextElement();
            System.out.println(key + "=" + (String)params.get(key));
        }
    }

    public SSLTest(String[] args) {
      try {

        initParams();
        processArgs(args);
        dumpParams();
        CryptoManager.initialize(".");

        int port = (new Integer( (String) params.get("port") )).intValue();

        Socket s = new Socket((String)params.get("host"), port);

        SSLSocket ss = new SSLSocket(s, (String)params.get("remotehost"),
            null, null);

        ss.setSoTimeout(5000);

        OutputStream os = ss.getOutputStream();
        String writeString = "GET / HTTP/1.0\n\n";
        byte[] writeBytes = writeString.getBytes("8859_1");
        os.write(writeBytes);

        InputStream is = ss.getInputStream();
        int numRead = 0;
        byte[] inbuf = new byte[256];
        while( (numRead = is.read(inbuf)) != -1 ) {
            System.out.print( new String(inbuf, 0, numRead, "UTF-8"));
        }

        ss.setKeepAlive(true);
        ss.setReceiveBufferSize(32000);
        ss.setSendBufferSize(8000);
        ss.setSoLinger(true, 10);
        ss.setTcpNoDelay(true);

        System.out.println("remote addr is " + ss.getInetAddress().toString());
        System.out.println("remote port is " + ss.getPort());
        System.out.println("local addr is " + ss.getLocalAddress().toString());
        System.out.println("local port is " + ss.getLocalPort());
        System.out.println("keepalive is " + ss.getKeepAlive());
        System.out.println("receive buffer size is " + ss.getReceiveBufferSize());
        System.out.println("send buffer size is " + ss.getSendBufferSize());
        System.out.println("solinger is " + ss.getSoLinger());
        System.out.println("sotimeout is " + ss.getSoTimeout());
        System.out.println("tcpNoDelay is " + ss.getTcpNoDelay());

        ss.shutdownInput();
        ss.shutdownOutput();

        ss.close();

      } catch(Exception e) {
            e.printStackTrace();
      }
      try {
        Runtime.getRuntime().gc();
      }catch(Exception e) {
        e.printStackTrace();
      }
    }
}
