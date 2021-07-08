package org.mozilla.jss.netscape.security.x509;

import org.junit.Assert;
import org.junit.Test;

public class RevocationReasonTest {

    private static RevocationReason before = RevocationReason.KEY_COMPROMISE;

    @Test
    public void testJSON() throws Exception {
        // Act
        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        RevocationReason afterJSON = RevocationReason.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        // Assert
        Assert.assertEquals(before, afterJSON);
    }

}
