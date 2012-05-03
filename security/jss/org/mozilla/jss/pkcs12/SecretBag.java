/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs12;

import org.mozilla.jss.asn1.*;
import org.mozilla.jss.util.Assert;
import java.io.*;

public class SecretBag implements ASN1Value {

    ///////////////////////////////////////////////////////////////////////
    // members and member access
    ///////////////////////////////////////////////////////////////////////
    private OBJECT_IDENTIFIER secretType;
    private ANY secret;
    private SEQUENCE sequence;

    /**
     * Returns the type of secret stored in the SecretBag.
     */
    public OBJECT_IDENTIFIER getSecretType() {
        return secretType;
    }

    /**
     * Returns the secret stored in the SecretBag.
     */
    public ANY getSecret() {
        return secret;
    }

    ///////////////////////////////////////////////////////////////////////
    // Constructors
    ///////////////////////////////////////////////////////////////////////
    private SecretBag() { }

    /**
     * Creates a SecretBag with the given secret type and secret.  Neither
     * may be null.
     */
    public SecretBag(OBJECT_IDENTIFIER secretType, ASN1Value secret) {
        if( secretType==null || secret==null ) {
            throw new IllegalArgumentException("SecretBag parameter is null");
        }

        this.secretType = secretType;
        if( secret instanceof ANY ) {
            this.secret = (ANY) secret;
        } else {
            byte[] encoded = ASN1Util.encode(secret);
            try {
                this.secret = (ANY) ASN1Util.decode(ANY.getTemplate(), encoded);
            } catch(InvalidBERException e) {
                Assert.notReached("Failed to convert ASN1Value to ANY");
            }
        }

        sequence = new SEQUENCE();
        sequence.addElement(secretType);
        sequence.addElement( new EXPLICIT(new Tag(0), this.secret) );
    }

    ///////////////////////////////////////////////////////////////////////
    // DER encoding
    ///////////////////////////////////////////////////////////////////////

    private static final Tag TAG = SEQUENCE.TAG;
    public Tag getTag() {
        return TAG;
    }

    public void encode(OutputStream ostream) throws IOException {
        sequence.encode(ostream);
    }

    public void encode(Tag implicitTag, OutputStream ostream)
        throws IOException
    {
        sequence.encode(implicitTag, ostream);
    }

    private static final Template templateInstance = new Template();
    public static Template getTemplate() {
        return templateInstance;
    }

    /**
     * A Template class for decoding SecretBags from BER.
     */
    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement( OBJECT_IDENTIFIER.getTemplate() );
            seqt.addElement( new EXPLICIT.Template(
                                new Tag(0), ANY.getTemplate()) );
        }

        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        public ASN1Value decode(InputStream istream)
            throws InvalidBERException, IOException
        {
            return decode(TAG, istream);
        }

        public ASN1Value decode(Tag implicitTag, InputStream istream)
            throws InvalidBERException, IOException
        {
            SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag, istream);

            return new SecretBag( (OBJECT_IDENTIFIER)seq.elementAt(0),
                            ((EXPLICIT)seq.elementAt(1)).getContent() );
        }
    }
}
