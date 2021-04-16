/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs10;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.InvalidKeyFormatException;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.primitive.Name;

/**
 * A pkcs10 signed CertificationRequest.
 */
public class CertificationRequest implements ASN1Value {

    private CertificationRequestInfo info;
    private byte[] infoEncoding;
    private byte[] signature;
    private AlgorithmIdentifier algId;
    SEQUENCE sequence;

    CertificationRequest(CertificationRequestInfo info,
						 //byte[] infoEncoding,
            AlgorithmIdentifier algId, byte[] signature) throws IOException
    {
        this.info = info;
        //this.infoEncoding = infoEncoding;
        this.algId = algId;
        this.signature = signature;

        // bundle everything into a SEQUENCE
        sequence = new SEQUENCE();
        sequence.addElement( info );
        sequence.addElement( algId );
        sequence.addElement( new BIT_STRING( signature, 0 ) );
    }

    /**
     * Creates and signs an X.509 CertificationRequest.
     * @param info A CertificationRequestInfo (TBSCertificationRequest),
     *      which specifies
     *      the actual information of the CertificationRequest.
     * @param privKey The private key with which to sign the certificate.
     * @param signingAlg The algorithm to use to sign the CertificationRequest.
     *      It must match the algorithm specified in the CertificationRequestInfo.
     * @exception IOException If an error occurred while encoding the
     *      CertificationRequest.
     * @exception NotInitializedException Because this
     *      operation involves cryptography (signing), CryptoManager must
     *      be initialized before calling it.
     * @exception TokenException If an error occurs on a PKCS #11 token.
     * @exception NoSuchAlgorithmException If the OID for the signing algorithm
     *      cannot be located.
     * @exception CertificateException If the signing algorithm specified
     *      as a parameter does not match the one in the CertificationRequest info.
     * @exception InvalidKeyException If the key does not match the signing
     *      algorithm.
     * @exception SignatureException If an error occurs while signing the
     *      CertificationRequest.
     */
    public CertificationRequest(CertificationRequestInfo info, java.security.PrivateKey privKey,
                SignatureAlgorithm signingAlg)
        throws IOException, NotInitializedException,
            TokenException, NoSuchAlgorithmException, CertificateException,
            InvalidKeyException, SignatureException
    {
        // make sure key is a Ninja private key
        if( !(privKey instanceof PrivateKey) ) {
            throw new InvalidKeyException("Private Key is does not belong to"+
                " this provider");
        }
        PrivateKey priv = (PrivateKey)privKey;

        // create algId
        if(signingAlg.getSigningAlg() == SignatureAlgorithm.RSASignature) {
            algId = new AlgorithmIdentifier( signingAlg.toOID(), null );
        } else {
            algId = new AlgorithmIdentifier( signingAlg.toOID() );
        }

        // encode the cert info
        this.info = info;
        infoEncoding = ASN1Util.encode(info);

        // sign the info encoding
        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = priv.getOwningToken();
        Signature sig = token.getSignatureContext(signingAlg);
        sig.initSign(priv);
        sig.update(infoEncoding);
        signature = sig.sign();

        // bundle everything into a SEQUENCE
        sequence = new SEQUENCE();
        sequence.addElement( info );
        sequence.addElement( algId );
        sequence.addElement( new BIT_STRING( signature, 0 ) );
    }

    /**
     * Verifies the signature on this CertificationRequest.  Does not indicate
     * that the CertificationRequest is valid at any specific time.
     */
    public void verify()
        throws InvalidKeyException, NotInitializedException,
        NoSuchAlgorithmException, CertificateException, TokenException,
        SignatureException, InvalidKeyFormatException
    {
        verify( info.getSubjectPublicKeyInfo().toPublicKey() );
    }

    /**
     * Verifies the signature on this CertificationRequest, using the given public key.
     * Does not indicate the CertificationRequest is valid at any specific time.
     */
    public void verify(PublicKey key)
        throws InvalidKeyException, NotInitializedException,
        NoSuchAlgorithmException, CertificateException, TokenException,
        SignatureException
    {
        CryptoManager cm = CryptoManager.getInstance();
        verify(key, cm.getInternalCryptoToken());
    }

    /**
     * Verifies the signature on this CertificationRequest, using the given public
     * key and CryptoToken. Does not indicate the CertificationRequest is valid at
     * any specific time.
     */
    public void verify(PublicKey key, CryptoToken token)
        throws NoSuchAlgorithmException, CertificateException, TokenException,
            SignatureException, InvalidKeyException
    {
        Signature sig = token.getSignatureContext(
            SignatureAlgorithm.fromOID( algId.getOID() ) );

        sig.initVerify(key);
        sig.update(infoEncoding);
        if( ! sig.verify(signature) ) {
            throw new CertificateException("Signature is invalid");
        }
    }


    /**
     * Returns the information (TBSCertificationRequest) contained in this CertificationRequest.
     */
    public CertificationRequestInfo getInfo() {
        return info;
    }

    private static final Tag TAG = SEQUENCE.TAG;
    public Tag getTag() {
        return TAG;
    }

    public void encode(OutputStream ostream) throws IOException {
        encode(TAG, ostream);
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

    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement( CertificationRequestInfo.getTemplate() );
            //seqt.addElement( new ANY.Template() );
            seqt.addElement( AlgorithmIdentifier.getTemplate() );
            seqt.addElement( BIT_STRING.getTemplate() );
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

            //ANY infoAny = (ANY)seq.elementAt(0);
            //byte[] infoEncoding = infoAny.getEncoded();
            /*CertificationRequestInfo info = (CertificationRequestInfo) infoAny.decodeWith(
                                        CertificationRequestInfo.getTemplate() );
										*/
            CertificationRequestInfo info = (CertificationRequestInfo) seq.elementAt(0);
            // although signature is a bit string, all algorithms we use
            // will produce an octet string.
            BIT_STRING bs = (BIT_STRING) seq.elementAt(2);
            if( bs.getPadCount() != 0 ) {
                throw new InvalidBERException("signature does not fall into"+
                    " an integral number of bytes");
            }
            byte[] signature = bs.getBits();

            return new CertificationRequest( info,
											//infoEncoding,
                                    (AlgorithmIdentifier) seq.elementAt(1),
                                    signature
                        );
        }
    }
}
