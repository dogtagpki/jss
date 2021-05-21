/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.primitive;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;

import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.asn1.Tag;
import org.mozilla.jss.crypto.PrivateKey;

public class PrivateKeyInfo
    implements ASN1Value, java.security.PrivateKey {

    private static final long serialVersionUID = 1L;
    ///////////////////////////////////////////////////////////////////////
    // members and member access
    ///////////////////////////////////////////////////////////////////////
    private INTEGER version;
    private AlgorithmIdentifier privateKeyAlgorithm;
    private OCTET_STRING privateKey;
    private SET attributes; // may be null
    private SEQUENCE sequence;

    public INTEGER getVersion() {
        return version;
    }

    public AlgorithmIdentifier getPrivateKeyAlgorithm() {
        return privateKeyAlgorithm;
    }

    @Override
    public String getAlgorithm() {
        try {
            return PrivateKey.Type.fromOID(privateKeyAlgorithm.getOID())
                        .toString();
        } catch( NoSuchAlgorithmException e ) {
            return null;
        }
    }

    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        return privateKey.toByteArray();
    }

    public OCTET_STRING getPrivateKey() {
        return privateKey;
    }

    /**
     * May return null if no attributes are present.
     */
    public SET getAttributes() {
        return attributes;
    }

    ///////////////////////////////////////////////////////////////////////
    // Constructors
    ///////////////////////////////////////////////////////////////////////

    /**
     * Create a PrivateKeyInfo from its components.
     *
     * @param attributes May be null if there are no attributes, in which
     *      case the attributes field will be omitted from the DER encoding.
     *      Each element must be a org.mozilla.jss.pkix.primitive.Attribute.
     */
    public PrivateKeyInfo(INTEGER version,
                AlgorithmIdentifier privateKeyAlgorithm,
                OCTET_STRING privateKey, SET attributes)
    {
        if( version==null || privateKeyAlgorithm==null || privateKey==null ) {
            throw new IllegalArgumentException(
                    "PrivateKeyInfo parameter is null");
        }

        this.version = version;
        this.privateKeyAlgorithm = privateKeyAlgorithm;
        this.privateKey = privateKey;
        this.attributes = attributes;

        sequence = new SEQUENCE();
        sequence.addElement(version);
        sequence.addElement(privateKeyAlgorithm);
        sequence.addElement(privateKey);

        if(attributes!=null) {
            sequence.addElement( new Tag(0), attributes );

            // make sure all the attributes are Attributes
            int size = attributes.size();
            for(int i=0; i < size; i++) {
                if( ! (attributes.elementAt(i) instanceof Attribute) ) {
                    throw new IllegalArgumentException("element "+i+
                        " of attributes is not an Attribute");
                }
            }
        }
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
     * A template class for decoding PrivateKeyInfos from BER.
     */
    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();

            seqt.addElement( INTEGER.getTemplate() );
            seqt.addElement( AlgorithmIdentifier.getTemplate() );
            seqt.addElement( OCTET_STRING.getTemplate() );
            seqt.addOptionalElement( new Tag(0),
                        new SET.OF_Template( Attribute.getTemplate() ) );
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

            return new PrivateKeyInfo( (INTEGER) seq.elementAt(0),
                                        (AlgorithmIdentifier) seq.elementAt(1),
                                        (OCTET_STRING) seq.elementAt(2),
                                        (SET) seq.elementAt(3) );
        }
    }
}
