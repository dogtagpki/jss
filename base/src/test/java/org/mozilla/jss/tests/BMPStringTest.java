package org.mozilla.jss.tests;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BMPStringTest {

    public static Logger logger = LoggerFactory.getLogger(BMPStringTest.class);

    public byte tag = DerValue.tag_BMPString;

    @Test
    public void testEncodingEmptyString() throws Exception {

        String string = "";
        logger.debug("Encoding: [" + string + "]");

        byte[] expected = JSSUtil.encode(tag, string);
        logger.debug(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = StringTestUtil.encode(tag, string);
        logger.debug(" - actual  : " + StringTestUtil.toString(actual));

        Assertions.assertArrayEquals(expected, actual);
    }

    @Test
    public void testDecodingEmptyString() throws Exception {

        String input = "";
        byte[] data = JSSUtil.encode(tag, input);

        logger.debug("Decoding: [" + StringTestUtil.toString(data) + "]");

        logger.debug(" - expected: [" + input + "]");

        String output = StringTestUtil.decode(tag, data);
        logger.debug(" - actual  : [" + output + "]");

        Assertions.assertEquals(input, output);
    }

    @Test
    public void testEncodingNullCharacters() throws Exception {

        String string = StringTestUtil.NULL_CHARS;
        logger.debug("Encoding: [" + StringTestUtil.toString(string.getBytes()) + "]");

        byte[] expected = JSSUtil.encode(tag, string);
        logger.debug(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = StringTestUtil.encode(tag, string);
        logger.debug(" - actual  : " + StringTestUtil.toString(actual));

        actual = StringTestUtil.normalizeUnicode(actual);
        logger.debug(" - norm.   : " + StringTestUtil.toString(actual));

        Assertions.assertArrayEquals(expected, actual);
    }

    @Test
    public void testDecodingNullCharacters() throws Exception {

        String input = StringTestUtil.NULL_CHARS;
        byte[] data = JSSUtil.encode(tag, input);

        logger.debug("Decoding: [" + StringTestUtil.toString(data) + "]");

        logger.debug(" - expected: [" + StringTestUtil.toString(input.getBytes()) + "]");

        String output = StringTestUtil.decode(tag, data);
        logger.debug(" - actual  : [" + StringTestUtil.toString(output.getBytes()) + "]");

        Assertions.assertEquals(input, output);
    }

    @Test
    public void testEncodingPrintableCharacters() throws Exception {

        String string = StringTestUtil.PRINTABLE_CHARS;
        logger.debug("Encoding: [" + string + "]");

        byte[] expected = JSSUtil.encode(tag, string);
        logger.debug(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = StringTestUtil.encode(tag, string);
        logger.debug(" - actual  : " + StringTestUtil.toString(actual));

        actual = StringTestUtil.normalizeUnicode(actual);
        logger.debug(" - norm.   : " + StringTestUtil.toString(actual));

        Assertions.assertArrayEquals(expected, actual);
    }

    @Test
    public void testDecodingPrintableCharacters() throws Exception {

        String input = StringTestUtil.PRINTABLE_CHARS;
        byte[] data = JSSUtil.encode(tag, input);

        logger.debug("Decoding: [" + StringTestUtil.toString(data) + "]");

        logger.debug(" - expected: [" + input + "]");

        String output = StringTestUtil.decode(tag, data);
        logger.debug(" - actual  : [" + output + "]");

        Assertions.assertEquals(input, output);
    }

    @Test
    public void testEncodingNonPrintableCharacters() throws Exception {

        String string = StringTestUtil.NON_PRINTABLE_CHARS;
        logger.debug("Encoding: [" + string + "]");

        byte[] expected = JSSUtil.encode(tag, string);
        logger.debug(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = StringTestUtil.encode(tag, string);
        logger.debug(" - actual  : " + StringTestUtil.toString(actual));

        actual = StringTestUtil.normalizeUnicode(actual);
        logger.debug(" - norm.   : " + StringTestUtil.toString(actual));

        Assertions.assertArrayEquals(expected, actual);
    }

    @Test
    public void testDecodingNonPrintableCharacters() throws Exception {

        String input = StringTestUtil.NON_PRINTABLE_CHARS;
        byte[] data = JSSUtil.encode(tag, input);

        logger.debug("Decoding: [" + StringTestUtil.toString(data) + "]");

        logger.debug(" - expected: [" + input + "]");

        String output = StringTestUtil.decode(tag, data);
        logger.debug(" - actual  : [" + output + "]");

        Assertions.assertEquals(input, output);
    }

    @Test
    public void testEncodingControlCharacters() throws Exception {

        String string = StringTestUtil.CONTROL_CHARS;
        logger.debug("Encoding: [" + StringTestUtil.toString(string.getBytes()) + "]");

        byte[] expected = JSSUtil.encode(tag, string);
        logger.debug(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = StringTestUtil.encode(tag, string);
        logger.debug(" - actual  : " + StringTestUtil.toString(actual));

        actual = StringTestUtil.normalizeUnicode(actual);
        logger.debug(" - norm.   : " + StringTestUtil.toString(actual));

        Assertions.assertArrayEquals(expected, actual);
    }

    @Test
    public void testDecodingControlCharacters() throws Exception {

        String input = StringTestUtil.CONTROL_CHARS;
        byte[] data = JSSUtil.encode(tag, input);

        logger.debug("Decoding: [" + StringTestUtil.toString(data) + "]");

        logger.debug(" - expected: [" + StringTestUtil.toString(input.getBytes()) + "]");

        String output = StringTestUtil.decode(tag, data);
        logger.debug(" - actual  : [" + StringTestUtil.toString(output.getBytes()) + "]");

        Assertions.assertEquals(input, output);
    }

    @Test
    public void testEncodingMultibyteCharacters() throws Exception {

        String string = StringTestUtil.MULTIBYTE_CHARS;
        logger.debug("Encoding: [" + string + "]");

        byte[] expected = JSSUtil.encode(tag, string);
        logger.debug(" - expected: " + StringTestUtil.toString(expected));

        byte[] actual = StringTestUtil.encode(tag, string);
        logger.debug(" - actual  : " + StringTestUtil.toString(actual));

        actual = StringTestUtil.normalizeUnicode(actual);
        logger.debug(" - norm.   : " + StringTestUtil.toString(actual));

        Assertions.assertArrayEquals(expected, actual);
    }

    @Test
    public void testDecodingMultibyteCharacters() throws Exception {

        String input = StringTestUtil.MULTIBYTE_CHARS;
        byte[] data = JSSUtil.encode(tag, input);

        logger.debug("Decoding: [" + StringTestUtil.toString(data) + "]");

        logger.debug(" - expected: [" + StringTestUtil.toString(input.getBytes()) + "]");

        String output = StringTestUtil.decode(tag, data);
        logger.debug(" - actual  : [" + StringTestUtil.toString(output.getBytes()) + "]");

        Assertions.assertEquals(input, output);
    }

    @Test
    public void testEncodingTime() throws Exception {

        logger.debug("Encoding time:");

        String string = StringTestUtil.NULL_CHARS +
                StringTestUtil.PRINTABLE_CHARS +
                StringTestUtil.NON_PRINTABLE_CHARS +
                StringTestUtil.CONTROL_CHARS +
                StringTestUtil.MULTIBYTE_CHARS;

        long t0 = System.currentTimeMillis();

        for (int i = 0; i < 10000; i++)
            JSSUtil.encode(tag, string);

        long t1 = System.currentTimeMillis();

        for (int i = 0; i < 10000; i++)
            StringTestUtil.encode(tag, string);

        long t2 = System.currentTimeMillis();

        long time1 = t1 - t0;
        long time2 = t2 - t1;

        logger.debug(" - JSS     : " + time1 + " ms");
        logger.debug(" - Internal: " + time2 + " ms");
    }

    @Test
    public void testDecodingTime() throws Exception {

        logger.debug("Decoding time:");

        String string = StringTestUtil.NULL_CHARS +
                StringTestUtil.PRINTABLE_CHARS +
                StringTestUtil.NON_PRINTABLE_CHARS +
                StringTestUtil.CONTROL_CHARS +
                StringTestUtil.MULTIBYTE_CHARS;

        byte[] data = JSSUtil.encode(tag, string);

        long t0 = System.currentTimeMillis();

        for (int i = 0; i < 10000; i++)
            JSSUtil.decode(tag, data);

        long t1 = System.currentTimeMillis();

        for (int i = 0; i < 10000; i++)
            StringTestUtil.decode(tag, data);

        long t2 = System.currentTimeMillis();

        long time1 = t1 - t0;
        long time2 = t2 - t1;

        logger.debug(" - JSS     : " + time1 + " ms");
        logger.debug(" - Internal: " + time2 + " ms");
    }
}
