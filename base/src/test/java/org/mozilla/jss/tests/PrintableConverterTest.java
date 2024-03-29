package org.mozilla.jss.tests;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.x509.PrintableConverter;

public class PrintableConverterTest {

    @Test
    public void testEmptyString() throws Exception {

        String string = "";
        System.out.println("Converting: [" + string + "]");

        byte[] expected = JSSUtil.encode(DerValue.tag_PrintableString, string);
        System.out.println(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = ConverterTestUtil.convert(new PrintableConverter(), string);
        System.out.println(" - actual  : " + StringTestUtil.toString(actual));

        Assertions.assertArrayEquals(expected, actual);
    }

    @Test
    public void testNullCharacters() throws Exception {

        String string = StringTestUtil.NULL_CHARS;
        System.out.println("Converting: [" + StringTestUtil.toString(string.getBytes()) + "]");

        System.out.println(" - expected: IllegalArgumentException");

        try {
            byte[] actual = ConverterTestUtil.convert(new PrintableConverter(), string);
            System.out.println(" - actual  : " + StringTestUtil.toString(actual));

            Assertions.fail();

        } catch (Exception e) {
            System.out.println(" - actual  : " + e.getClass().getSimpleName());
            Assertions.assertTrue(e instanceof IllegalArgumentException);
        }
    }

    @Test
    public void testPrintableCharacters() throws Exception {

        String string = StringTestUtil.PRINTABLE_CHARS;
        System.out.println("Converting: [" + string + "]");

        byte[] expected = JSSUtil.encode(DerValue.tag_PrintableString, string);
        System.out.println(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = ConverterTestUtil.convert(new PrintableConverter(), string);
        System.out.println(" - actual  : " + StringTestUtil.toString(actual));

        Assertions.assertArrayEquals(expected, actual);
    }

    @Test
    public void testControlCharacters() throws Exception {

        String string = StringTestUtil.CONTROL_CHARS;
        System.out.println("Converting: [" + StringTestUtil.toString(string.getBytes()) + "]");

        System.out.println(" - expected: IllegalArgumentException");

        try {
            byte[] actual = ConverterTestUtil.convert(new PrintableConverter(), string);
            System.out.println(" - actual  : " + StringTestUtil.toString(actual));

            Assertions.fail();

        } catch (Exception e) {
            System.out.println(" - actual  : " + e.getClass().getSimpleName());
            Assertions.assertTrue(e instanceof IllegalArgumentException);
        }
    }

    @Test
    public void testMultibyteCharacters() throws Exception {

        String string = StringTestUtil.MULTIBYTE_CHARS;
        System.out.println("Converting: [" + string + "]");

        System.out.println(" - expected: IllegalArgumentException");

        try {
            byte[] actual = ConverterTestUtil.convert(new PrintableConverter(), string);
            System.out.println(" - actual  : " + StringTestUtil.toString(actual));

            Assertions.fail();

        } catch (Exception e) {
            System.out.println(" - actual  : " + e.getClass().getSimpleName());
            Assertions.assertTrue(e instanceof IllegalArgumentException);
        }
    }
}
