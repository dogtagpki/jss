/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.asn1;

import java.io.IOException;
import java.io.OutputStream;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Random;

/**
 * The ASN.1 type <code>INTEGER</code>. This class extends BigInteger.
 */
public class INTEGER extends BigInteger implements ASN1Value {

    private byte[] encodedContents = null;
    private byte[] getEncodedContents() {
        if( encodedContents == null ) {
            encodedContents = toByteArray();
        }
        return encodedContents;
    }

    private ASN1Header getHeader(Tag t) {
        return new ASN1Header( t, FORM, getContentLength() );
    }

    public INTEGER(String s) throws NumberFormatException {
        super(s);
    }

    public INTEGER(String s, int r) throws NumberFormatException {
        super(s, r);
    }

    public INTEGER(byte[] bval) throws NumberFormatException  {
        super(bval);
    }

    public INTEGER(int sign, byte[] mag) throws NumberFormatException {
        super(sign, mag);
    }

    public INTEGER(int numBits, Random rnd) throws NumberFormatException {
        super(numBits, rnd);
    }

    public INTEGER(int bitLength, int certainty, Random rnd) {
        super(bitLength, certainty, rnd);
    }

    public INTEGER(long val) {
        super( BigInteger.valueOf(val).toByteArray() );
    }

    public INTEGER(BigInteger bi) {
        super( bi.toByteArray() );
    }
        
    public static final Tag TAG = new Tag(Tag.Class.UNIVERSAL, 2);
    public Tag getTag() {
        return TAG;
    }
    public static final Form FORM = Form.PRIMITIVE;

    public void encode(OutputStream outStream) throws IOException {
        encode(getTag(), outStream);
    }

    public void encode(Tag implicitTag, OutputStream outStream)
        throws IOException
    {
        // write header
        getHeader(implicitTag).encode( outStream );

        // write contents
        outStream.write( getEncodedContents() );
    }

    public long getContentLength() {
        return getEncodedContents().length;
    }

    public byte[] encode() throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        encode(b);
        return b.toByteArray();
    }

    private static final INTEGER.Template templateInstance =
                                            new INTEGER.Template();
    public static ASN1Template getTemplate() {
        return templateInstance;
    }

    /**
     * Tests the DER encoding and decoding of the INTEGER class.
     */
    public static void main(String args[]) {
        try {
            int[] Is = new int[11];
            int[][] Bs = new int[11][];
            int i = 0;

            Is[i] = 0;
            Bs[i++] = new int[]{ 0x02, 0x01, 0x00 };

            Is[i] = 1;
            Bs[i++] = new int[]{ 0x02, 0x01, 0x01 };

            Is[i] = -1;
            Bs[i++] = new int[]{ 0x02, 0x01, 0xff };

            Is[i] = 127;
            Bs[i++] = new int[]{ 0x02, 0x01, 0x7f };

            Is[i] = 128;
            Bs[i++] = new int[]{ 0x02, 0x02, 0x00, 0x80 };

            Is[i] = 255;
            Bs[i++] = new int[]{ 0x02, 0x02, 0x00, 0xff };

            Is[i] = 256;
            Bs[i++] = new int[]{ 0x02, 0x02, 0x01, 0x00 };

            Is[i] = -128;
            Bs[i++] = new int[]{ 0x02, 0x01, 0x80 };

            Is[i] = -129;
            Bs[i++] = new int[]{ 0x02, 0x02, 0xff, 0x7f };

            Is[i] = 43568;
            Bs[i++] = new int[]{ 0x02, 0x03, 0x00, 0xaa, 0x30 };

            Is[i] = -43568;
            Bs[i++] = new int[]{ 0x02, 0x03, 0xff, 0x55, 0xd0 };

            for( i = 0; i < Is.length; i++) {
                INTEGER I = new INTEGER( Is[i] );
                byte[] compare = I.encode();
                if( ! arraysEqual(compare, Bs[i]) ) {
                    System.err.println("Encoding FAILED: "+Is[i]);
                    System.exit(-1);
                }

                ByteArrayInputStream bis = new ByteArrayInputStream(compare);
                Template template = new Template();
                INTEGER create = (INTEGER) template.decode(bis);
                if( create.intValue() != Is[i] ) {
                    System.err.println("Decoding FAILED: "+Is[i]);
                    System.exit(-1);
                }
            }
            System.out.println("PASS");

        } catch( Exception e ) {
            e.printStackTrace();
        }
    }

    private static boolean arraysEqual(byte[] bytes, int[] ints) {
        if(bytes == null || ints == null) {
            return false;
        }

        if(bytes.length != ints.length) {
            return false;
        }

        for( int i=0; i < bytes.length; i++) {
            if( bytes[i] != (byte)ints[i] ) {
                return false;
            }
        }
        return true;
    }

///////////////////////////////////////////////////////////////////////
// INTEGER.Template
// This is a nested class.
//
public static class Template implements ASN1Template {

    Tag getTag() {
        return INTEGER.TAG;
    }
    public boolean tagMatch(Tag tag) {
        return( tag.equals(INTEGER.TAG));
    }

    public ASN1Value
    decode(InputStream derStream)
        throws InvalidBERException, IOException
    {
        return decode( getTag(), derStream );
    }

    public ASN1Value
    decode(Tag tag, InputStream derStream)
        throws InvalidBERException, IOException
    {
      try {
        ASN1Header wrapper = new ASN1Header(derStream);

        wrapper.validate(tag, FORM);

        // Is length < 1 ?
        if( wrapper.getContentLength() < 1 ) {
            throw new InvalidBERException("Invalid 0 length for INTEGER");
        }

        byte[] valBytes = new byte[ (int) wrapper.getContentLength() ];
        ASN1Util.readFully(valBytes, derStream);
        return new INTEGER( valBytes );

      } catch(InvalidBERException e) {
        throw new InvalidBERException(e, "INTEGER");
      }
    }
} // end of class Template

}
