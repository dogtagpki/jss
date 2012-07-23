/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.cmmf;

import org.mozilla.jss.asn1.*;
import java.io.OutputStream;
import java.io.IOException;
import org.mozilla.jss.util.Assert;
import java.io.ByteArrayOutputStream;

public class CertOrEncCert implements ASN1Value {

    private ANY certificate;
    byte[] encoding;

    /**
     * @exception InvalidBERException If the certificate is not a valid
     *      BER-encoding.
     */
    public CertOrEncCert(byte[] encodedCert) throws IOException,
            InvalidBERException
    {
        certificate = new ANY( new Tag(0), encodedCert );
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        certificate.encodeWithAlternateTag(new Tag(0), bos);
        encoding = bos.toByteArray();
    }

    public static final Tag TAG = new Tag(0);
    public Tag getTag() {
        return TAG;
    }

    public void encode(OutputStream ostream) throws IOException {
        ostream.write(encoding);
    }

    /**
     * @param implicitTag <b>This parameter is ignored</b>, because a CHOICE
     *  cannot have an implicit tag.
     */
    public void encode(Tag implicitTag, OutputStream ostream)
        throws IOException
    {
        Assert._assert( implicitTag.equals(TAG) );
        ostream.write(encoding);
    }
}
