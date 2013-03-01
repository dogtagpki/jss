/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs12;

import org.mozilla.jss.crypto.KeyGenerator;
import org.mozilla.jss.util.Assert;

/**
 * Converts password chars to bytes.  The output format is big-endian Unicode,
 * with two zero bytes of null-termination at the end.
 */
public final class PasswordConverter
    implements KeyGenerator.CharToByteConverter {

        public byte[] convert(char[] chars) {
            byte[] bytes = new byte[ (chars.length+1) * 2 ];

            int c; // char index
            int b; // byte index
            for(c=0, b=0; c < chars.length; c++) {
                bytes[b++] = (byte) ((chars[c] & 0xff00) >>> 8);
                bytes[b++] = (byte) (chars[c] & 0xff);
            }
            bytes[b++] = 0;
            bytes[b++] = 0;
            Assert._assert(b == bytes.length);

            return bytes;
        }
    }
        
