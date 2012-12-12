/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.cmmf;

import org.mozilla.jss.asn1.*;
import org.mozilla.jss.util.Assert;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class CertResponse implements ASN1Value {

    private INTEGER certReqId;
    private PKIStatusInfo status;
    private CertifiedKeyPair certifiedKeyPair;

    private CertResponse() { }

    public CertResponse(INTEGER certReqId, PKIStatusInfo status) {
        this.certReqId = certReqId;
        this.status = status;
    }

    public CertResponse(INTEGER certReqId, PKIStatusInfo status,
            CertifiedKeyPair certifiedKeyPair)
    {
        this(certReqId, status);
        this.certifiedKeyPair = certifiedKeyPair;
    }

    public INTEGER getCertReqId() {
        return certReqId;
    }

    public PKIStatusInfo getPKIStatusInfo() {
        return status;
    }

    /**
     * Returns <code>true</code> if the certifiedKeyPair field is present.
     */
    public boolean hasCertifiedKeyPair() {
        return (certifiedKeyPair != null);
    }

    /**
     * Returns the optional certified key pair. Should only be called if
     * the certifiedKeyPair field is present.
     */
    public CertifiedKeyPair getCertifiedKeyPair() {
        Assert._assert(certifiedKeyPair!=null);
        return certifiedKeyPair;
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
        seq.addElement( certReqId );
        seq.addElement( status );
        if( certifiedKeyPair != null ) {
            seq.addElement( certifiedKeyPair );
        }

        seq.encode(implicitTag, ostream);
    }
}
