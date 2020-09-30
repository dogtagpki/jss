package org.mozilla.jss.netscape.security.util;

import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;

public class UniversalCharset extends Charset {

    public UniversalCharset() {
        super("ASN.1-Universal", null);
    }

    @Override
    public boolean contains(Charset cs) {
        return false;
    }

    @Override
    public CharsetDecoder newDecoder() {
        return new UniversalCharsetDecoder(this);
    }

    @Override
    public CharsetEncoder newEncoder() {
        return new UniversalCharsetEncoder(this);
    }
}
