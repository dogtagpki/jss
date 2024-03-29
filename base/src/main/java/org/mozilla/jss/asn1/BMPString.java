/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.asn1;

import java.io.CharConversionException;
import java.io.UnsupportedEncodingException;

/**
 * The ASN.1 type <i>BMPString</i>. BMPStrings use the Unicode character set.
 * They are encoded and decoded in big-endian format using two octets.
 */
public class BMPString extends CharacterString {

    /**
     * Creates a new BMPString from an array of Java characters.
     *
     * @param chars Input characters.
     * @throws CharConversionException If an error occurred.
     */
    public BMPString(char[] chars) throws CharConversionException {
        super(chars);
    }

    /**
     * Creates a new BMPString from a Java String.
     *
     * @param s Input string.
     * @throws CharConversionException If an error occurred.
     */
    public BMPString(String s) throws CharConversionException {
        super(s);
    }

    /**
     * Returns the conversion object for converting between an encoded byte
     * array an an array of Java characters.
     *
     * @return Character converter.
     */
    @Override
    CharConverter getCharConverter() {
        return converterInstance;
    }

    private static final BMPConverter converterInstance = new BMPConverter();

    static final Tag TAG = new Tag(Tag.UNIVERSAL, 30);
    static final Form FORM = Form.PRIMITIVE;

    @Override
    public Tag getTag() {
        return TAG;
    }

    /**
     * Returns a singleton instance of BMPString.Template. This is more
     * efficient than creating a new BMPString.Template.
     *
     * @return BMSString template.
     */
    public static Template getTemplate() {
        return templateInstance;
    }

    private static final Template templateInstance = new Template();

    // nested class
    public static class Template extends CharacterString.Template {
        @Override
        protected Tag getTag() {
            return TAG;
        }

        @Override
        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        @Override
        protected CharConverter getCharConverter() {
            return new BMPConverter();
        }

        @Override
        protected CharacterString generateInstance(char[] chars)
                throws CharConversionException {
            return new BMPString(chars);
        }

        @Override
        protected String typeName() {
            return "BMPString";
        }
    }

    private static class BMPConverter implements CharConverter {

        @Override
        public char[] byteToChar(byte[] bytes, int offset, int len)
                throws CharConversionException {
            try {
                String s = new String(bytes, offset, len, "UnicodeBig");
                return s.toCharArray();

            } catch (UnsupportedEncodingException e) {
                String err = "Unable to find UnicodeBig encoding mechanism";
                throw (CharConversionException) new CharConversionException(err).initCause(e);
            }
        }

        @Override
        public byte[] charToByte(char[] chars, int offset, int len)
                throws CharConversionException {
            try {
                // We don't want the byte-order mark
                String s = new String(chars, offset, len);
                return s.getBytes("UnicodeBigUnmarked");

            } catch (UnsupportedEncodingException e) {
                String err = "Unable to find UnicodeBigUnmarked encoding mechanism";
                throw (CharConversionException) new CharConversionException(err).initCause(e);
            }
        }
    } // end of char converter

}
