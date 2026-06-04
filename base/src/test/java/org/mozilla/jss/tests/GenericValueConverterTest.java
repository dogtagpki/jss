package org.mozilla.jss.tests;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.x509.GenericValueConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GenericValueConverterTest {

    public static Logger logger = LoggerFactory.getLogger(GenericValueConverterTest.class);

    @Test
    public void testEmptyString() throws Exception {

        String string = "";
        logger.debug("Converting: [" + string + "]");

        byte[] expected = JSSUtil.encode(DerValue.tag_PrintableString, string);
        logger.debug(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = ConverterTestUtil.convert(new GenericValueConverter(), string);
        logger.debug(" - actual  : " + StringTestUtil.toString(actual));

        Assertions.assertArrayEquals(expected, actual);
    }

    @Test
    public void testNullCharacters() throws Exception {

        String string = StringTestUtil.NULL_CHARS;
        logger.debug("Converting: [" + StringTestUtil.toString(string.getBytes()) + "]");

        byte[] expected = JSSUtil.encode(DerValue.tag_IA5String, string);
        logger.debug(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = ConverterTestUtil.convert(new GenericValueConverter(), string);
        logger.debug(" - actual  : " + StringTestUtil.toString(actual));

        Assertions.assertArrayEquals(expected, actual);
    }

    @Test
    public void testPrintableCharacters() throws Exception {

        String string = StringTestUtil.PRINTABLE_CHARS;
        logger.debug("Converting: [" + string + "]");

        byte[] expected = JSSUtil.encode(DerValue.tag_PrintableString, string);
        logger.debug(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = ConverterTestUtil.convert(new GenericValueConverter(), string);
        logger.debug(" - actual  : " + StringTestUtil.toString(actual));

        Assertions.assertArrayEquals(expected, actual);
    }

    @Test
    public void testControlCharacters() throws Exception {

        String string = StringTestUtil.CONTROL_CHARS;
        logger.debug("Converting: [" + StringTestUtil.toString(string.getBytes()) + "]");

        byte[] expected = JSSUtil.encode(DerValue.tag_IA5String, string);
        logger.debug(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = ConverterTestUtil.convert(new GenericValueConverter(), string);
        logger.debug(" - actual  : " + StringTestUtil.toString(actual));

        Assertions.assertArrayEquals(expected, actual);
    }

    @Test
    public void testMultibyteCharacters() throws Exception {

        String string = StringTestUtil.MULTIBYTE_CHARS;
        logger.debug("Converting: [" + string + "]");

        byte[] expected = JSSUtil.encode(DerValue.tag_BMPString, string);
        logger.debug(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = ConverterTestUtil.convert(new GenericValueConverter(), string);
        logger.debug(" - actual  : " + StringTestUtil.toString(actual));

        actual = StringTestUtil.normalizeUnicode(actual);
        logger.debug(" - norm.   : " + StringTestUtil.toString(actual));

        Assertions.assertArrayEquals(expected, actual);
    }

    @Test
    public void testPrintableCharactersWithTags() throws Exception {

        String string = StringTestUtil.PRINTABLE_CHARS;
        logger.debug("Converting: [" + string + "]");

        byte[] expected = JSSUtil.encode(DerValue.tag_T61String, string);
        logger.debug(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = ConverterTestUtil.convert(new GenericValueConverter(), string, new byte[] {
                DerValue.tag_T61String, DerValue.tag_UniversalString
        });
        logger.debug(" - actual  : " + StringTestUtil.toString(actual));

        Assertions.assertArrayEquals(expected, actual);
    }

    @Test
    public void testMultibyteCharactersWithTags() throws Exception {

        String string = StringTestUtil.MULTIBYTE_CHARS;
        logger.debug("Converting: [" + string + "]");

        byte[] expected = JSSUtil.encode(DerValue.tag_UniversalString, string);
        logger.debug(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = ConverterTestUtil.convert(new GenericValueConverter(), string, new byte[] {
                DerValue.tag_T61String, DerValue.tag_UniversalString
        });
        logger.debug(" - actual  : " + StringTestUtil.toString(actual));

        Assertions.assertArrayEquals(expected, actual);
    }
}
