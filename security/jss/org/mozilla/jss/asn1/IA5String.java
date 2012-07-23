/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.asn1;

import java.io.CharConversionException;

public class IA5String extends CharacterString implements ASN1Value {

    public IA5String(char[] chars) throws CharConversionException {
        super(chars);
    }

    public IA5String(String s) throws CharConversionException {
        super(s);
    }

    CharConverter getCharConverter() {
        return new IA5Converter();
    }

    public static final Tag TAG = new Tag( Tag.Class.UNIVERSAL, 22 );

    public Tag getTag() {
        return TAG;
    }

    public static Template getTemplate() {
        return templateInstance;
    }
    private static final Template templateInstance = new Template();

// nested class
public static class Template
    extends CharacterString.Template implements ASN1Template
{
    public Tag getTag() {
        return IA5String.TAG;
    }
    public boolean tagMatch(Tag tag) {
        return( tag.equals( IA5String.TAG ));
    }

    protected CharConverter getCharConverter() {
        return new IA5Converter();
    }

    protected CharacterString generateInstance(char[] chars)
        throws CharConversionException
    {
        return new IA5String(chars);
    }

    protected String typeName() {
        return "IA5String";
    }
}

// nested class
private static class IA5Converter implements CharConverter {

    public char[] byteToChar(byte[] bytes, int offset, int len)
        throws CharConversionException
    {
        char[] chars = new char[len];

        int c; // char index
        int b; // byte index
        for(b = offset, c=0; c < len; b++, c++) {
            if( (bytes[b] & 0x80) != 0 ) {
                throw new CharConversionException("Invalid character: "+
                    bytes[b]);
            }
            chars[c] = (char) (bytes[b] & 0x7f);
        }
        return chars;
    }

    public byte[] charToByte(char[] chars, int offset, int len)
        throws CharConversionException
    {
        byte[] bytes = new byte[len];

        int c; // char index
        int b; // byte index
        for(c = offset, b = 0; b < len; c++, b++) {
            if( (chars[c] & 0x7f) != chars[c] ) {
                throw new CharConversionException("Invalid character: "+
                    chars[c]);
            }
            bytes[b] = (byte) (chars[c] & 0x7f);
        }

        return bytes;
    }
}

}
