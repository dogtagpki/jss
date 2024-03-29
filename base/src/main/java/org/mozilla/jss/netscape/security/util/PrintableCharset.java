package org.mozilla.jss.netscape.security.util;

import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;

public class PrintableCharset extends Charset {

    public PrintableCharset() {
        super("ASN.1-Printable", null);
    }

    public static boolean isPrintableChar(char c) {
        return (c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9')
                || c == ' '
                || c == '\''
                || c == '('
                || c == ')'
                || c == '+'
                || c == ','
                || c == '-'
                || c == '.'
                || c == '/'
                || c == ':'
                || c == '='
                || c == '?';
    }

    @Override
    public boolean contains(Charset cs) {
        return false;
    }

    @Override
    public CharsetDecoder newDecoder() {
        return new PrintableCharsetDecoder(this);
    }

    @Override
    public CharsetEncoder newEncoder() {
        return new PrintableCharsetEncoder(this);
    }
}
