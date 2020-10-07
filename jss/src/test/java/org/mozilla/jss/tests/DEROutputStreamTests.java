package org.mozilla.jss.tests;

import org.mozilla.jss.netscape.security.util.*;
import java.math.*;

public class DEROutputStreamTests {
    public static void assert_f(boolean expr, String location) {
        if (!expr) {
            System.err.println("Assertion: " + location);
            assert(expr);
        }
    }

    public static void testInteger(int value, byte[] expected) throws Exception {
        DerOutputStream out = new DerOutputStream();
        BigInt num = new BigInt(value);
        out.putInteger(num);

        byte[] actual = out.toByteArray();
        assert_f(actual.length == expected.length, "value=" + value);
        for (int i = 0; i < actual.length; i++) {
            assert_f(actual[i] == expected[i], "value=" + value + "|i=" + i);
        }
    }

    public static void testIntegers() throws Exception {
        int[] values = {0, 127, 128, 256};
        byte[][] expected = {{0x02, 0x01, 0x00},
                             {0x02, 0x01, 0x7F},
                             {0x02, 0x02, 0x00, (byte) 0x80},
                             {0x02, 0x02, 0x01, 0x00}};

        assert_f(values.length == expected.length, "testIntegers test cases");
        for (int i = 0; i < values.length; i++ ) {
            testInteger(values[i], expected[i]);
        }
    }

    public static void testEnumeration(int value, byte[] expected) throws Exception {
        DerOutputStream out = new DerOutputStream();
        out.putEnumerated(value);

        byte[] actual = out.toByteArray();
        assert_f(actual.length == expected.length, "value=" + value);
        for (int i = 0; i < actual.length; i++ ) {
            assert_f(actual[i] == expected[i], "value=" + value + "|i=" + i);
        }
    }

    public static void testEnumerations() throws Exception {
        int[] values = {0, 1, 127, 128, 256, -128, -129};
        byte[][] expected = {{0x0A, 0x01, 0x00},
                             {0x0A, 0x01, 0x01},
                             {0x0A, 0x01, 0x7F},
                             {0x0A, 0x02, 0x00, (byte) 0x80},
                             {0x0A, 0x02, 0x01, 0x00},
                             {0x0A, 0x01, (byte) 0x80},
                             {0x0A, 0x02, (byte) 0xFF, 0x7F}};

        assert(values.length == expected.length);
        for (int i = 0; i < values.length; i++ ) {
            testEnumeration(values[i], expected[i]);
        }
    }

    public static void main(String[] args) throws Exception {
        testIntegers();
        testEnumerations();
    }
}
