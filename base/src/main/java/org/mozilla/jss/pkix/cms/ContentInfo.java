/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.pkix.cms;

import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.pkcs7.DigestedData;
import org.mozilla.jss.pkcs7.EncryptedData;
import org.mozilla.jss.pkcs7.EnvelopedData;
import org.mozilla.jss.pkcs7.SignedAndEnvelopedData;
import org.mozilla.jss.pkcs7.SignedData;

/**
 * A PKCS #7 ContentInfo structure.
 */
public class ContentInfo extends org.mozilla.jss.pkcs7.ContentInfo {

    public ContentInfo(byte[] data) {
        super(data);
    }

    public ContentInfo(DigestedData dd) {
        super(dd);
    }

    public ContentInfo(EncryptedData ed) {
        super(ed);
    }

    public ContentInfo(EnvelopedData ed) {
        super(ed);
    }

    public ContentInfo(OBJECT_IDENTIFIER contentType, ASN1Value content) {
        super(contentType, content);
    }

    public ContentInfo(SignedAndEnvelopedData sed) {
        super(sed);
    }

    public ContentInfo(SignedData sd) {
        super(sd);
    }

}
