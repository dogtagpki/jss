/* 
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 * 
 * The Original Code is the Netscape Security Services for Java.
 * 
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation.  Portions created by Netscape are 
 * Copyright (C) 1998-2000 Netscape Communications Corporation.  All
 * Rights Reserved.
 * 
 * Contributor(s):
 * 
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable 
 * instead of those above.  If you wish to allow use of your 
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the
 * GPL.
 */

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
            Assert.assert(b == bytes.length);

            return bytes;
        }
    }
        
