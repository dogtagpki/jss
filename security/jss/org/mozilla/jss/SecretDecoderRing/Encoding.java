/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.SecretDecoderRing;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.pkix.primitive.*;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import java.io.*;

/**
 * An ASN.1 class for encoding the SecretDecoderRing result.
 * This class is used internally by the SecretDecoderRing. 
 * You need not use this class directly in order to use the SecretDecoderRing.
 */
public class Encoding implements ASN1Value {
    private SEQUENCE seq = new SEQUENCE();

    private byte[] iv;
    private OBJECT_IDENTIFIER encOID;
    private byte[] ctext;
    private byte[] keyID;

    public Encoding(byte[] keyID, byte[] iv, OBJECT_IDENTIFIER encOID,
            byte[] ctext)
    {
        this.keyID = keyID;
        this.iv = iv;
        this.encOID = encOID;
        this.ctext = ctext;
        AlgorithmIdentifier algID = new AlgorithmIdentifier(
            encOID, new OCTET_STRING(iv) );
        seq.addElement(new OCTET_STRING(keyID));
        seq.addElement(algID);
        seq.addElement(new OCTET_STRING(ctext));
    }

    public byte[] getKeyID() {
        return keyID;
    }

    public byte[] getIv() {
        return iv;
    }

    public OBJECT_IDENTIFIER getEncryptionOID() {
        return encOID;
    }

    public byte[] getCiphertext() {
        return ctext;
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
        seq.encode(implicitTag, ostream);
    }

    private static final Template templateInstance = new Template();
    public static Template getTemplate() {
        return templateInstance;
    }

    /**
     * An ASN.1 class for decoding the SecretDecoderRing result.
     * This class is used internally by the SecretDecoderRing. 
     * You need not use this class directly in order to use the
     * SecretDecoderRing.
    */
    public static class Template extends SEQUENCE.Template {
        private SEQUENCE.Template template;

        public Template() {
            template = new SEQUENCE.Template();
            template.addElement(OCTET_STRING.getTemplate() );
            template.addElement(AlgorithmIdentifier.getTemplate() );
            template.addElement(OCTET_STRING.getTemplate() );
        }

        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        public ASN1Value decode(InputStream istream)
            throws IOException, InvalidBERException
        {
            return decode(TAG, istream);
        }

        public ASN1Value decode(Tag implicitTag, InputStream istream)
            throws IOException, InvalidBERException
        {
            SEQUENCE seq = (SEQUENCE) template.decode(implicitTag, istream);

            OCTET_STRING keyID = (OCTET_STRING) seq.elementAt(0);
            AlgorithmIdentifier algID = (AlgorithmIdentifier)
                seq.elementAt(1);
            OCTET_STRING ivOS = (OCTET_STRING)
                ((ANY)algID.getParameters()).decodeWith(
                        OCTET_STRING.getTemplate());
            OCTET_STRING ctextOS = (OCTET_STRING)seq.elementAt(2);

            return new Encoding(keyID.toByteArray(),
                ivOS.toByteArray(), algID.getOID(),
                ctextOS.toByteArray());
        }
    }
}


