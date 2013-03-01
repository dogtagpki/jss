/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.cmmf;

import org.mozilla.jss.asn1.*;
import java.io.OutputStream;
import java.io.IOException;
import org.mozilla.jss.util.Assert;

public class CertifiedKeyPair implements ASN1Value {

    private CertOrEncCert certOrEncCert;

    public CertifiedKeyPair(CertOrEncCert certOrEncCert) {
        this.certOrEncCert = certOrEncCert;
    }

    public static final Tag TAG = SEQUENCE.TAG;
    public Tag getTag() {
        return TAG;
    }

    public void encode(OutputStream ostream) throws IOException {
        encode(TAG, ostream);
    }

    public void encode(Tag implicitTag, OutputStream ostream)
        throws IOException
    {
        SEQUENCE seq = new SEQUENCE();
        seq.addElement( certOrEncCert );
        seq.encode(implicitTag, ostream);
    }
}
