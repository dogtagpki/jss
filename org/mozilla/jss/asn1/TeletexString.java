/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.asn1;

import java.io.CharConversionException;

/**
 * The ASN.1 type <i>TeletexString</i>.
 */
public class TeletexString extends CharacterString implements ASN1Value {

    public static final Tag TAG = new Tag(Tag.UNIVERSAL, 20);
    public Tag getTag() {
        return TAG;
    }

    public TeletexString(char[] chars) throws CharConversionException {
        super(chars);
    }

    public TeletexString(String s) throws CharConversionException {
        super(s);
    }

    CharConverter getCharConverter() {
        return new TeletexConverter();
    }

    /**
     * Returns a singleton instance of the decoding template for this class.
     */
    public static Template getTemplate() {
        return templateInstance;
    }
    private static final Template templateInstance = new Template();

// nested class
public static class Template
    extends CharacterString.Template implements ASN1Template
{

    protected Tag getTag() {
        return TAG;
    }

    public boolean tagMatch(Tag tag) {
        return TAG.equals(tag);
    }

    protected CharConverter getCharConverter() {
        return new TeletexConverter();
    }

    protected CharacterString generateInstance(char[] bytes)
        throws CharConversionException
    {
        return new TeletexString( bytes );
    }

    protected String typeName() {
        return "TeletexString";
    }
} // end of Template

    private static class TeletexConverter implements CharConverter {

        public char[] byteToChar(byte[] bytes, int offset, int len)
            throws CharConversionException
        {
            char[] chars = new char[len];

            int b;
            int c;
            for(b=offset, c=0; c < len; b++, c++) {
                chars[c] = (char) (bytes[b] & 0xff);
            }
            return chars;
        }

        public byte[] charToByte(char[] chars, int offset, int len)
            throws CharConversionException
        {
            byte[] bytes = new byte[len];

            int b;
            int c;
            for(b=0, c=offset; b < len; b++, c++) {
                if( (chars[c]&0xff00) != 0 ) {
                    throw new CharConversionException("Invalid character for"+
                        " TeletexString");
                }
                bytes[b] = (byte) (chars[c] & 0xff);
            }
            return bytes;
        }
    }
}
