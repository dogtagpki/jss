/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.asn1;

import java.io.CharConversionException;

interface CharConverter {

    public char[] byteToChar(byte[] bytes, int offset, int len)
		throws CharConversionException;

    public byte[] charToByte(char[] chars, int offset, int len)
		throws CharConversionException;

}
