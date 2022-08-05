/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.primitive;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;

/**
 * PKCS #5 <i>PBES2Parameter</i>
 */
public class PBES2Params implements ASN1Value {

    ///////////////////////////////////////////////////////////////////////
    // members and member access
    ///////////////////////////////////////////////////////////////////////
    private AlgorithmIdentifier keyDerivationFunc;
    private AlgorithmIdentifier encryptionScheme;
    private SEQUENCE sequence;

    public AlgorithmIdentifier getKeyDerivationFunc() {
        return keyDerivationFunc;
    }

    public AlgorithmIdentifier getEncryptionScheme() {
        return encryptionScheme;
    }


    ///////////////////////////////////////////////////////////////////////
    // constructors
    ///////////////////////////////////////////////////////////////////////


    public PBES2Params(AlgorithmIdentifier keyDerivationFunc, AlgorithmIdentifier encryptionScheme) {
        this.keyDerivationFunc = keyDerivationFunc;
        this.encryptionScheme = encryptionScheme;
        sequence = new SEQUENCE();
        sequence.addElement( keyDerivationFunc );
        sequence.addElement( encryptionScheme );
    }

    ///////////////////////////////////////////////////////////////////////
    // DER encoding
    ///////////////////////////////////////////////////////////////////////

    private static final Tag TAG = SEQUENCE.TAG;
    @Override
    public Tag getTag() {
        return TAG;
    }

    @Override
    public void encode(OutputStream ostream) throws IOException {
        sequence.encode(ostream);
    }

    @Override
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
     * A template class for decoding a PBES2Params.
     */
    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement( AlgorithmIdentifier.getTemplate() );
            seqt.addElement( AlgorithmIdentifier.getTemplate() );
        }

        @Override
        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        @Override
        public ASN1Value decode(InputStream istream)
            throws InvalidBERException, IOException
        {
            return decode(TAG, istream);
        }

        @Override
        public ASN1Value decode(Tag implicitTag, InputStream istream)
            throws InvalidBERException, IOException
        {
            SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag, istream);

            return new PBES2Params( (AlgorithmIdentifier) seq.elementAt(0),
                                     (AlgorithmIdentifier)      seq.elementAt(1) );
        }
    }
}
