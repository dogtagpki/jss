/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.tests;

import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;

import org.apache.commons.lang3.RandomStringUtils;
import org.mozilla.jss.util.Assert;
import org.mozilla.jss.util.UTF8Converter;

public class UTF8ConverterTest {

    public UTF8ConverterTest() throws Exception {
    }

    public void testUnicodeToUTF8() throws Exception {
        // Verify UnicodeToUTF8 by comparing its output
        // to that of the standard Java conversion routines.

        String input = RandomStringUtils.random(10);
        char[] unicode = input.toCharArray();

        System.out.print("Input:");
        for (int c : unicode) {
            System.out.print(String.format(" %04x", c));
        }
        System.out.println();

        byte[] utf8 = UTF8Converter.UnicodeToUTF8(unicode);

        System.out.print("Output 1:");
        for (byte b : utf8) {
            System.out.print(String.format(" %02x", b));
        }
        System.out.println();

        ByteArrayOutputStream barray = new ByteArrayOutputStream();

        OutputStreamWriter writer = new OutputStreamWriter(barray, "UTF8");
        writer.write(unicode, 0, unicode.length);
        writer.close();

        byte[] output = barray.toByteArray();

        System.out.print("Output 2:");
        for (byte b : output) {
            System.out.print(String.format(" %02x", b));
        }
        System.out.println();

        assert(utf8 != null);

        assert(utf8.length == output.length);

        for(int i=0; i<output.length; i++) {
            assert(utf8[i] == output[i]);
        }
    }

    public static void main(String[] argv) {
        try {
            UTF8ConverterTest test = new UTF8ConverterTest();
            test.testUnicodeToUTF8();
            System.exit(0);

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}

