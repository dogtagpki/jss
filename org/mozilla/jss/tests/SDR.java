/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.tests;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.SecretDecoderRing;
import org.mozilla.jss.util.ConsolePasswordCallback;

public class SDR {

    public static void main(String[] args) {

      try {
        CryptoManager.initialize(".");

        String cmd = args[0];
        String infile = args[1];
        String outfile = args[2];

        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();
        token.login(new ConsolePasswordCallback());

        SecretDecoderRing sdr = new SecretDecoderRing();

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        int numread;
        byte[] data = new byte[1024];

        try (FileInputStream fis = new FileInputStream(infile)) {
            while ((numread = fis.read(data)) != -1) {
                bos.write(data, 0, numread);
            }
        }

        byte[] inputBytes = bos.toByteArray();

        byte[] outputBytes;
        if( cmd.equalsIgnoreCase("encrypt") ) {
               outputBytes = sdr.encrypt(inputBytes);
        } else {
                outputBytes = sdr.decrypt(inputBytes);
        }

        try (FileOutputStream fos = new FileOutputStream(outfile)) {
            fos.write(outputBytes);
        }

      } catch(Exception e) {
        e.printStackTrace();
        System.exit(1);
      }
      System.exit(0);
    }

    private static char[] hex = new char[]
        { '0', '1', '2', '3', '4', '5', '6', '7',
          '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
}
