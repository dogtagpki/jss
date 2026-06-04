package org.mozilla.jss.tests;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.x509.PrintableConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PrintableConverterTest {

    public static Logger logger = LoggerFactory.getLogger(PrintableConverterTest.class);

    @Test
    public void testEmptyString() throws Exception {

        String string = "";
        logger.debug("Converting: [" + string + "]");

        byte[] expected = JSSUtil.encode(DerValue.tag_PrintableString, string);
        logger.debug(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = ConverterTestUtil.convert(new PrintableConverter(), string);
        logger.debug(" - actual  : " + StringTestUtil.toString(actual));

        Assertions.assertArrayEquals(expected, actual);
    }

    @Test
    public void testNullCharacters() throws Exception {

        String string = StringTestUtil.NULL_CHARS;
        logger.debug("Converting: [" + StringTestUtil.toString(string.getBytes()) + "]");

        logger.debug(" - expected: IllegalArgumentException");

        try {
            byte[] actual = ConverterTestUtil.convert(new PrintableConverter(), string);
            logger.debug(" - actual  : " + StringTestUtil.toString(actual));

            Assertions.fail();

        } catch (Exception e) {
            logger.debug(" - actual  : " + e.getClass().getSimpleName());
            Assertions.assertTrue(e instanceof IllegalArgumentException);
        }
    }

    @Test
    public void testPrintableCharacters() throws Exception {

        String string = StringTestUtil.PRINTABLE_CHARS;
        logger.debug("Converting: [" + string + "]");

        byte[] expected = JSSUtil.encode(DerValue.tag_PrintableString, string);
        logger.debug(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = ConverterTestUtil.convert(new PrintableConverter(), string);
        logger.debug(" - actual  : " + StringTestUtil.toString(actual));

        Assertions.assertArrayEquals(expected, actual);
    }

    @Test
    public void testControlCharacters() throws Exception {

        String string = StringTestUtil.CONTROL_CHARS;
        logger.debug("Converting: [" + StringTestUtil.toString(string.getBytes()) + "]");

        logger.debug(" - expected: IllegalArgumentException");

        try {
            byte[] actual = ConverterTestUtil.convert(new PrintableConverter(), string);
            logger.debug(" - actual  : " + StringTestUtil.toString(actual));

            Assertions.fail();

        } catch (Exception e) {
            logger.debug(" - actual  : " + e.getClass().getSimpleName());
            Assertions.assertTrue(e instanceof IllegalArgumentException);
        }
    }

    @Test
    public void testMultibyteCharacters() throws Exception {

        String string = StringTestUtil.MULTIBYTE_CHARS;
        logger.debug("Converting: [" + string + "]");

        logger.debug(" - expected: IllegalArgumentException");

        try {
            byte[] actual = ConverterTestUtil.convert(new PrintableConverter(), string);
            logger.debug(" - actual  : " + StringTestUtil.toString(actual));

            Assertions.fail();

        } catch (Exception e) {
            logger.debug(" - actual  : " + e.getClass().getSimpleName());
            Assertions.assertTrue(e instanceof IllegalArgumentException);
        }
    }
}
