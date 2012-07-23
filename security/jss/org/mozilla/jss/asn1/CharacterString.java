/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.asn1;

import java.io.CharConversionException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.io.ByteArrayOutputStream;

/**
 * An abstract base class for all character string types in ASN.1.
 */
public abstract class CharacterString implements ASN1Value {

    abstract CharConverter getCharConverter();

    public abstract Tag getTag();
    static final Form FORM = Form.PRIMITIVE;

    private char[] chars;

    /**
     * Converts this ASN.1 character string to a Java String.
     */
    public String toString() {
        return new String(chars);
    }

    /**
     * Converts this ASN.1 character string to an array of Java characters.
     */
    public char[] toCharArray() {
        return chars;
    }

    protected CharacterString(char[] chars) throws CharConversionException {
        this.chars = chars;
        cachedContents = computeContents();
    }

    protected CharacterString(String s) throws CharConversionException {
        this.chars = s.toCharArray();
        cachedContents = computeContents();
    }

    private byte[] cachedContents;

    private byte[] getEncodedContents() {
        return cachedContents;
    }

    private byte[] computeContents() throws CharConversionException {
        CharConverter converter = getCharConverter();

        byte[] contents = converter.charToByte(chars, 0, chars.length);

        return contents;
    }

    public void encode(OutputStream ostream) throws IOException {
        encode( getTag(), ostream );
    }

    public void encode( Tag implicitTag, OutputStream ostream )
        throws IOException
    {
        byte[] contents = getEncodedContents();
        ASN1Header head = new ASN1Header( implicitTag, FORM, contents.length);

        head.encode(ostream);

        ostream.write( contents );
    }

public abstract static class Template implements ASN1Template {

    /**
     * Must be overridden to return the tag for the subclass.
     */
    protected abstract Tag getTag();

    public abstract boolean tagMatch(Tag tag);

    /**
     * Must be overridden to return the correct character converter
     * for the subclass.
     */
    protected abstract CharConverter getCharConverter();

    /**
     * Must be overridden to create an instance of the subclass given
     * a char array.
     */
    protected abstract CharacterString generateInstance(char[] chars)
        throws CharConversionException;

    /**
     * Must be overridden to provide the name of the subclass, for including
     * into error messages.
     */
    protected abstract String typeName();

    public ASN1Value decode(InputStream istream)
        throws IOException, InvalidBERException
    {
        return decode(getTag(), istream);
    }

    public ASN1Value decode(Tag implicitTag, InputStream istream)
        throws IOException, InvalidBERException
    {
      try {
        ASN1Header head = new ASN1Header(istream);

        head.validate(implicitTag);

        byte[] raw; // raw bytes, not translated to chars yet

        if( head.getContentLength() == -1 ) {
            // indefinite length encoding
            ASN1Header ahead;
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            do {
                ahead = ASN1Header.lookAhead( istream );
                if( ! ahead.isEOC() ) {
                    OCTET_STRING.Template ot = new OCTET_STRING.Template();
                    OCTET_STRING os = (OCTET_STRING) ot.decode(istream);
                    bos.write( os.toByteArray() );
                }
            } while( ! ahead.isEOC() );

            // consume EOC
            ahead = new ASN1Header(istream);

            raw = bos.toByteArray();
        } else {
            // definite length
            raw = new byte[ (int) head.getContentLength() ];
            ASN1Util.readFully(raw, istream);
        }

        char[] chars = getCharConverter().byteToChar(raw, 0, raw.length);

        return generateInstance(chars);

      } catch( CharConversionException e ) {
        throw new InvalidBERException(e.getMessage());
      } catch( InvalidBERException e ) {
        throw new InvalidBERException(e, typeName());
      }
    }
}

}
