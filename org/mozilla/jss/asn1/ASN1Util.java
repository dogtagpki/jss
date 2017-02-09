/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.asn1;

import java.io.*;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.util.Assert;

public class ASN1Util {

    public static byte[] encode(ASN1Value val) {
        return encode(val.getTag(), val);
    }

    public static byte[] encode(Tag implicitTag, ASN1Value val)
    {
      try {

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        val.encode(implicitTag, bos);
        return bos.toByteArray();

      } catch( IOException e ) {
        Assert.notReached("Encoding to byte array gave IOException");
        return null;
      }
    }

    public static ASN1Value decode(ASN1Template template, byte[] encoded)
        throws InvalidBERException
    {
      try {

        ByteArrayInputStream bis = new ByteArrayInputStream(encoded);
        return template.decode(bis);

      } catch( IOException e ) {
        Assert.notReached("Decoding from byte array gave IOException");
        return null;
      }
    }
    
    public static ASN1Value decode(Tag implicitTag, ASN1Template template,
                            byte[] encoded)
        throws InvalidBERException
    {
      try {

        ByteArrayInputStream bis = new ByteArrayInputStream(encoded);
        return template.decode(implicitTag, bis);

      } catch( IOException e ) {
        Assert.notReached("Decoding from byte array gave IOException");
        return null;
      }
    }



    /**
     * Fills a byte array with bytes from an input stream.  This method
     * keeps reading until the array is filled, an IOException occurs, or EOF
     * is reached.  The byte array will be completely filled unless an
     * exception is thrown.
     *
     * @param bytes A byte array which will be filled up.
     * @param istream The input stream from which to read the bytes.
     * @exception IOException If an IOException occurs reading from the
     *      stream, or EOF is reached before the byte array is filled.
     */
    public static void readFully(byte[] bytes, InputStream istream)
        throws IOException
    {

        int numRead=0;
        while(numRead < bytes.length) {
            int nr = istream.read(bytes, numRead, bytes.length-numRead);
            if( nr == -1 ) {
                throw new EOFException();
            }
            numRead += nr;
        }
    }
}
