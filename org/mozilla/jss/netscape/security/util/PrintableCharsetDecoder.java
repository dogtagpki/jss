// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.mozilla.jss.netscape.security.util;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;

/**
 * Converts bytes in ASN.1 PrintableString character set to PrintableString
 * characters.
 *
 * @author Lily Hsiao
 * @author Slava Galperin
 */

public class PrintableCharsetDecoder extends CharsetDecoder {

    public PrintableCharsetDecoder(Charset cs) {
        super(cs, 1, 1);
    }

    protected CoderResult decodeLoop(ByteBuffer in, CharBuffer out) {

        while (true) {

            if (in.remaining() < 1)
                return CoderResult.UNDERFLOW;

            in.mark();
            byte b = in.get();
            char c = (char) (b & 0x7f);

            if (CodingErrorAction.REPORT == unmappableCharacterAction() &&
                    !PrintableCharset.isPrintableChar(c)) {
                /*
                "bug" fix for 359010
                return CoderResult.unmappableForLength(1);
                */
                continue;
            }

            if (out.remaining() < 1) {
                in.reset();
                return CoderResult.OVERFLOW;
            }

            out.put(c);
        }
    }
}
