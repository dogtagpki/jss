/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.pkix.primitive;

import org.mozilla.jss.asn1.*;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import org.mozilla.jss.util.Assert;
import java.security.PublicKey;
import java.security.NoSuchAlgorithmException;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.InvalidKeyFormatException;
import org.mozilla.jss.pkcs11.PK11PubKey;

/**
 * A <i>SubjectPublicKeyInfo</i>, which stores information about a public key.
 * This class implements <code>java.security.PublicKey</code>.
 */
public class SubjectPublicKeyInfo extends java.security.spec.X509EncodedKeySpec
    implements ASN1Value, java.security.PublicKey {

    private AlgorithmIdentifier algorithm;
    private BIT_STRING subjectPublicKey;

    public String getAlgorithm() {
        try {
            return PrivateKey.Type.fromOID(algorithm.getOID()).toString();
        } catch( NoSuchAlgorithmException e ) {
            // unknown algorithm
            return null;
        }
    }

    public byte[] getEncoded() {
        return ASN1Util.encode(this);
    }
        

    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithm;
    }

    public BIT_STRING getSubjectPublicKey() {
        return subjectPublicKey;
    }

    private SubjectPublicKeyInfo() { super(new byte[] {0});}

    public SubjectPublicKeyInfo(AlgorithmIdentifier algorithm,
        BIT_STRING subjectPublicKey)
    {
        super( new byte[] {0} ); // super constructor can't handle null
        this.algorithm = algorithm;
        this.subjectPublicKey = subjectPublicKey;
    }

    public SubjectPublicKeyInfo(PublicKey pubk)
            throws InvalidBERException, IOException
    {
        super( new byte[] {0});
        SubjectPublicKeyInfo spki = (SubjectPublicKeyInfo)
            ASN1Util.decode( getTemplate(), pubk.getEncoded() );
        algorithm = spki.algorithm;
        subjectPublicKey = spki.subjectPublicKey;
    }

    public static final Tag TAG = SEQUENCE.TAG;

    public Tag getTag() {
        return TAG;
    }

    public void encode(OutputStream ostream) throws IOException {
        encode(TAG, ostream);
    }

    public void encode(Tag implicit, OutputStream ostream)
        throws IOException
    {
        SEQUENCE seq = new SEQUENCE();
        seq.addElement( algorithm );
        seq.addElement( subjectPublicKey );
        seq.encode( implicit, ostream );
    }

    private static final Template templateInstance = new Template();
    public static Template getTemplate() {
        return templateInstance;
    }

    /**
     * Creates a PublicKey from the public key information. Currently
     *      only RSA and DSA keys can be converted.
     *
     * @exception NoSuchAlgorithmException If the cryptographic provider
     *      does not recognize the algorithm for this public key.
     * @exception InvalidKeyFormatException If the subjectPublicKey could
     *      not be decoded correctly.
     */
    public PublicKey toPublicKey() throws NoSuchAlgorithmException,
            InvalidKeyFormatException
    {
        if( subjectPublicKey.getPadCount() != 0 ) {
            throw new InvalidKeyFormatException();
        }

        return PK11PubKey.fromSPKI(getEncoded());
    }

    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();

            seqt.addElement( AlgorithmIdentifier.getTemplate() );
            seqt.addElement( BIT_STRING.getTemplate() );
        }

        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        public ASN1Value decode(InputStream istream)
            throws IOException, InvalidBERException
        {
            return decode(TAG, istream);
        }

        public ASN1Value decode(Tag implicit, InputStream istream)
            throws IOException, InvalidBERException
        {
            SEQUENCE seq = (SEQUENCE) seqt.decode(implicit, istream);

            return new SubjectPublicKeyInfo(
                    (AlgorithmIdentifier) seq.elementAt(0),
                    (BIT_STRING) seq.elementAt(1)
            );
        }
    }
}
