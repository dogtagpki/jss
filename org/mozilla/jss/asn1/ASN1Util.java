/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.asn1;

import java.io.*;
import java.util.Arrays;

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

    /**
     * returns the ECC curve byte array given the X509 public key byte array
     *
     * @param X509PubKeyBytes byte array of an X509PubKey
     * @param withHeader tells if the return byes should inclulde the tag and size header or not
     */
    public static byte[] getECCurveBytesByX509PublicKeyBytes(byte[] X509PubKeyBytes,
        boolean withHeader)
        throws IllegalArgumentException, ArrayIndexOutOfBoundsException,
               NullPointerException
    {
        if ((X509PubKeyBytes == null) || (X509PubKeyBytes.length == 0)) {
            throw new IllegalArgumentException("X509PubKeyBytes null");
        }

        /* EC public key OID complete with tag and size */
        byte[] EC_PubOIDBytes_full =
            ASN1Util.encode(OBJECT_IDENTIFIER.EC_PUBKEY_OID);

        /* EC public key OID without tag and size */
        byte[] EC_PubOIDBytes =
            Arrays.copyOfRange(EC_PubOIDBytes_full, 2, EC_PubOIDBytes_full.length);

        int curveBeginIndex = 0;
        for (int idx = 0; idx<= X509PubKeyBytes.length; idx++) {
            byte[] tmp = 
                Arrays.copyOfRange(X509PubKeyBytes, idx, idx+EC_PubOIDBytes.length);
            if (Arrays.equals(tmp, EC_PubOIDBytes)) {
                curveBeginIndex = idx+ EC_PubOIDBytes.length;
                break;
            }
        }

        int curveByteArraySize = (int) X509PubKeyBytes[curveBeginIndex+ 1];

        if (withHeader) {
            /* actual curve with tag and size */
            byte curve[] = Arrays.copyOfRange(X509PubKeyBytes, curveBeginIndex, curveBeginIndex + curveByteArraySize + 2);
            return curve;
        } else {
            /* actual curve without tag and size */
            byte curve[] = 
                Arrays.copyOfRange(X509PubKeyBytes, curveBeginIndex + 2,
                    curveBeginIndex + 2 + curveByteArraySize);
            return curve;
        }
    }

    /**
     * getOIDdescription() returns a text description of the OID
     *     from OID byte array
     * the OID byte array is expected to be without the OID Tag (6) and size
     *    (together 2 bytes)
     */
    public static String
    getOIDdescription(byte[] oidBA) {
        return getTagDescriptionByOid(oidBA);
    }

    /**
     * get OID description JNI method
     */
    private native static String
    getTagDescriptionByOid(byte[] oidBA);


}
