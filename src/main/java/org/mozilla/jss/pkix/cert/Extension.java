/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.cert;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.BOOLEAN;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;

public class Extension implements ASN1Value {
    public static final Tag TAG = SEQUENCE.TAG;
    @Override
    public Tag getTag() {
        return TAG;
    }

    private OBJECT_IDENTIFIER extnId;
    /**
     * Returns the extension identifier.
     */
    public OBJECT_IDENTIFIER getExtnId() {
        return extnId;
    }

    private boolean critical;
    public boolean getCritical() {
        return critical;
    }

    private OCTET_STRING extnValue;
    public OCTET_STRING getExtnValue() {
        return extnValue;
    }

    public Extension( OBJECT_IDENTIFIER extnId, boolean critical,
        OCTET_STRING extnValue )
    {
        this.extnId = extnId;
        this.critical = critical;
        this.extnValue = extnValue;
    }

    @Override
    public void encode(OutputStream ostream) throws IOException {
        encode(TAG, ostream);
    }

    @Override
    public void encode(Tag implicit, OutputStream ostream) throws IOException {
        SEQUENCE seq = new SEQUENCE();

        seq.addElement( extnId );
        if( critical == true ) {
            // false is default, so we only code true
            seq.addElement( new BOOLEAN(true) );
        }
        seq.addElement( extnValue );

        seq.encode(implicit, ostream);
    }

    private static final Template templateInstance = new Template();
    public static Template getTemplate() {
        return templateInstance;
    }

    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement( OBJECT_IDENTIFIER.getTemplate() );
            seqt.addElement( BOOLEAN.getTemplate(), new BOOLEAN(false) );
            seqt.addElement( OCTET_STRING.getTemplate() );
        }

        @Override
        public boolean tagMatch(Tag t) {
            return TAG.equals(t);
        }

        @Override
        public ASN1Value decode(InputStream istream)
            throws IOException, InvalidBERException
        {
            return decode(TAG, istream);
        }

        @Override
        public ASN1Value decode(Tag implicit, InputStream istream)
            throws IOException, InvalidBERException
        {
            SEQUENCE seq = (SEQUENCE) seqt.decode(implicit, istream);

            return new Extension(
                (OBJECT_IDENTIFIER) seq.elementAt(0),
                ((BOOLEAN) seq.elementAt(1)).toBoolean(),
                (OCTET_STRING) seq.elementAt(2)
            );
        }
    }
}
