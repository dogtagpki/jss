package org.mozilla.jss.tests;

import java.io.IOException;
import org.mozilla.jss.netscape.security.util.DerValue;

/*
 * Regression test: check that a zero-length derValue doesn't create a parsing
 * exception.
 *
 * Fixed by Fraser Tweedale in https://github.com/dogtagpki/jss/pull/89
 *
 * Upstream Issue: https://pagure.io/dogtagpki/issue/3079
 */

class EmptyDerValue {
    public static void main(String[] args) throws Exception {
        byte[] bytes = { 0x04, 0x00 };
        DerValue derVal = new DerValue(bytes);
        System.out.println(derVal.getOctetString());
    }
}
