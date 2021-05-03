/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.cms;

import java.io.*;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.util.Assert;
import org.mozilla.jss.pkix.primitive.*;
import org.mozilla.jss.crypto.*;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.*;
import java.security.PublicKey;

/*
 * The high-level interface takes care of all
 * the logic and cryptography.  If you need to use the low-level interface,
 * please let us know what you are using it for. Perhaps it should be part
 * of the high-level interface.
 */

/**
 * A CMS <i>SignerInfo</i>.
 */
public class SignerInfo implements ASN1Value {

    ////////////////////////////////////////////////
    // PKCS #9 attributes
    ////////////////////////////////////////////////
    private static final OBJECT_IDENTIFIER
        CONTENT_TYPE = OBJECT_IDENTIFIER.PKCS.subBranch(9).subBranch(3);
    private static final OBJECT_IDENTIFIER
        MESSAGE_DIGEST = OBJECT_IDENTIFIER.PKCS.subBranch(9).subBranch(4);

    ///////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////
    // Members
    ///////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////

    private INTEGER version;
    private SignerIdentifier signerIdentifier;
    private AlgorithmIdentifier digestAlgorithm;
    private SET signedAttributes; // [0] OPTIONAL
    private AlgorithmIdentifier digestEncryptionAlgorithm;
    private OCTET_STRING encryptedDigest;
    private SET unsignedAttributes; // [1] OPTIONAL

    ///////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////
    // Accessor methods
    ///////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////

    /**
     * Retrieves the version number of this SignerInfo.
     */
    public INTEGER getVersion() {
        return version;
    }

    /**
     * Retrieves the SignerIdentifier.
     */
    public SignerIdentifier getSignerIdentifier() {
        return signerIdentifier;
    }

    /**
     * Retrieves the DigestAlgorithm used in this SignerInfo.
     *
     * @exception NoSuchAlgorithmException If the algorithm is not
     *  recognized by JSS.
     */
    public DigestAlgorithm getDigestAlgorithm()
        throws NoSuchAlgorithmException
    {
        return DigestAlgorithm.fromOID( digestAlgorithm.getOID() );
    }


    /**
     * Retrieves the DigestAlgorithmIdentifier used in this SignerInfo.
     */
    public AlgorithmIdentifier getDigestAlgorithmIdentifer() {
        return digestAlgorithm;
    }

    /**
     * Retrieves the signed attributes, if they exist.
     *
     */
    public SET getSignedAttributes() {
        return signedAttributes;
    }

    /**
     * Returns true if the signedAttributes field is present.
     */
    public boolean hasSignedAttributes() {
        return (signedAttributes != null);
    }

    /**
     * Returns the raw signature (digest encryption) algorithm used in this
     * SignerInfo.
     *
     * @exception NoSuchAlgorithmException If the algorithm is not recognized
     *  by JSS.
     */
    public SignatureAlgorithm getDigestEncryptionAlgorithm()
        throws NoSuchAlgorithmException
    {
        return SignatureAlgorithm.fromOID(
                    digestEncryptionAlgorithm.getOID() );
    }

    /**
     * Returns the DigestEncryptionAlgorithmIdentifier used in this SignerInfo.
     */
    public AlgorithmIdentifier getDigestEncryptionAlgorithmIdentifier() {
        return digestEncryptionAlgorithm;
    }

    /**
     * Retrieves the encrypted digest.
     */
    public byte[] getEncryptedDigest() {
        return encryptedDigest.toByteArray();
    }

    /**
     * Retrieves the unsigned attributes, if they exist.
     *
     */
    public SET getUnsignedAttributes() {
        return unsignedAttributes;
    }

    /**
     * Returns true if the unsignedAttributes field is present.
     */
    public boolean hasUnsignedAttributes() {
        return (unsignedAttributes!=null);
    }

    ///////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////
    // Constructors
    ///////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////

    /**
     * A constructor for creating a new SignerInfo from scratch.
     *
     * @param signerIdentifier The signerIdentifier of the
     *  certificate from which the public key was extracted to create
     *  this SignerInfo.
     * @param signingAlg The algorithm to be used to sign the content.
     *  This should be a composite algorithm, such as
	 *  RSASignatureWithMD5Digest, instead of a raw algorithm, such as
     *  RSASignature.
     *  Note that the digest portion of this algorithm must be the same
     *  algorithm as was used to digest the message content.
     * @param signedAttributes An optional set of Attributes, which
     *  will be signed along with the message content.  This parameter may
     *  be null, or the SET may be empty. DO NOT insert
     *  the PKCS #9 content-type or message-digest attributes.  They will
     *  be added automatically if they are necessary.
     * @param unsignedAttributes An optional set of Attributes, which
     *  will be included in the SignerInfo but not signed.  This parameter
     *  may be null, or the SET may be empty.
     * @param messageDigest The digest of the message contents.  The digest
     *  must have been created with the digest algorithm specified by
     *  the signingAlg parameter.
     * @param contentType The type of the ContentInfo that is being signed.
     *  If it is not <code>data</code>, then the PKCS #9 attributes
     *  content-type and message-digest will be automatically computed and
     *  added to the signed attributes.
     */
    public SignerInfo(  SignerIdentifier signerIdentifier,
                        SET signedAttributes,
                        SET unsignedAttributes,
                        OBJECT_IDENTIFIER contentType,
                        byte[] messageDigest,
                        SignatureAlgorithm signingAlg,
                        PrivateKey signingKey )
        throws InvalidKeyException, NoSuchAlgorithmException,
        NotInitializedException, SignatureException,
        TokenException
    {
        if (signerIdentifier == null) {
            throw new IllegalArgumentException("SignerIdentifier may not be null");
        }
        this.signerIdentifier = signerIdentifier;
        if (SignerIdentifier.ISSUER_AND_SERIALNUMBER.equals(this.signerIdentifier.getType())) {
            this.version = new INTEGER(1);
        } else if (SignerIdentifier.SUBJECT_KEY_IDENTIFIER.equals(this.signerIdentifier.getType())) {
            this.version = new INTEGER(3);
        } else {
            throw new IllegalArgumentException("Unexpected SignerIdentifier type");
        }
        this.digestAlgorithm =
                new AlgorithmIdentifier(signingAlg.getDigestAlg().toOID(),null);

        // if content-type is not data, add message-digest and content-type
        // to signed attributes.
        if( ! contentType.equals(ContentInfo.DATA) ) {
            if( signedAttributes == null ) {
                signedAttributes = new SET();
            }
            Attribute attrib = new Attribute(CONTENT_TYPE, contentType);
            signedAttributes.addElement(attrib);
            attrib = new Attribute(MESSAGE_DIGEST,
                            new OCTET_STRING(messageDigest) );
            signedAttributes.addElement(attrib);
        }

        digestEncryptionAlgorithm = new AlgorithmIdentifier(
            signingAlg.toOID(),null );


        if( signedAttributes != null ) 
        {
            assert( signedAttributes.size() >= 2 );
            this.signedAttributes = signedAttributes;
        }

        //////////////////////////////////////////////////
        // create encrypted digest (signature)
        //////////////////////////////////////////////////

        // compute the digest
        CryptoToken token = signingKey.getOwningToken();
        Signature sig;
        byte[] toBeSigned = null;
        if (signedAttributes == null) {
            // just use the message digest of the content
            if (signingAlg.getRawAlg() == SignatureAlgorithm.RSASignature) {
                SEQUENCE digestInfo = createDigestInfo(messageDigest, false);
                toBeSigned = ASN1Util.encode(digestInfo);
            } else {
                toBeSigned = messageDigest;
            }
            sig = token.getSignatureContext(signingAlg.getRawAlg()); //data is already digested
        } else {
            byte[] encoding = ASN1Util.encode(signedAttributes);
            if (signingAlg.getRawAlg() == SignatureAlgorithm.RSASignature) {
                // put the digest in a DigestInfo
                SEQUENCE digestInfo = createDigestInfo(encoding, true);
                toBeSigned = ASN1Util.encode(digestInfo);
                sig = token.getSignatureContext(SignatureAlgorithm.RSASignature);
            } else {
                toBeSigned = encoding;
                sig = token.getSignatureContext(signingAlg);
            }
        }
        
        // encrypt the DER-encoded DigestInfo with the private key
        sig.initSign(signingKey);
        sig.update(toBeSigned);
        encryptedDigest = new OCTET_STRING(sig.sign());

        if( unsignedAttributes != null )
        {
            this.unsignedAttributes = unsignedAttributes;
        }
    }

    /**
     * A constructor for creating a new SignerInfo from its decoding.
     */
    SignerInfo( INTEGER version,
            SignerIdentifier signerIdentifier,
            AlgorithmIdentifier digestAlgorithm,
            SET signedAttributes,
            AlgorithmIdentifier digestEncryptionAlgorithm,
            byte[] encryptedDigest,
            SET unsignedAttributes)
    {
        this.version = version;
        this.signerIdentifier = signerIdentifier;
        this.digestAlgorithm = digestAlgorithm;
        this.signedAttributes = signedAttributes;
        this.digestEncryptionAlgorithm = digestEncryptionAlgorithm;
        this.encryptedDigest = new OCTET_STRING(encryptedDigest);
        this.unsignedAttributes = unsignedAttributes;
    }

    ///////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////
    // Verification
    ///////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////

    /**
     * Verifies that this SignerInfo contains a valid signature of the
     * given message digest.  If any signed attributes are present,
     * they are also validated. The verification algorithm is as follows:
     * Note that this does <b>not</b> verify the validity of the
     *  the certificate itself, only the signature.<ul>
     *
     * <li>If no signed attributes are present, the content type is 
     *  verified to be <i>data</i>. Then it is verified that the message
     *  digest passed
     *  in, when encrypted with the given public key, matches the encrypted
     *  digest in the SignerInfo.
     *
     * <li>If signed attributes are present,
     *  two particular attributes must be present: <ul>
     *  <li>PKCS #9 Content-Type, the type of content that is being signed.
     *      This must match the contentType parameter.
     *  <li>PKCS #9 Message-Digest, the digest of the content that is being
     *      signed. This must match the messageDigest parameter.
     * </ul>
     * After these two attributes are verified to be both present and correct,
     * the encryptedDigest field of the SignerInfo is verified to be the
     * signature of the contents octets of the DER encoding of the
     * signedAttributes field.
     *
     * </ul>
     *
     * @param messageDigest The hash of the content that is signed by this
     *  SignerInfo.
     * @param contentType The type of the content that is signed by this
     *  SignerInfo.
     * @exception ObjectNotFoundException If no certificate
     *       matching the issuer name and serial number can be found.
     */
    public void verify(byte[] messageDigest, OBJECT_IDENTIFIER contentType)
        throws NotInitializedException, NoSuchAlgorithmException,
        InvalidKeyException, TokenException, SignatureException,
        ObjectNotFoundException
    {
        CryptoManager cm = CryptoManager.getInstance();
		if
			(signerIdentifier.getType().equals(SignerIdentifier.ISSUER_AND_SERIALNUMBER)) {
			IssuerAndSerialNumber issuerAndSerialNumber = signerIdentifier.getIssuerAndSerialNumber();
			X509Certificate cert = cm.findCertByIssuerAndSerialNumber(
				ASN1Util.encode(issuerAndSerialNumber.getIssuer()),
				issuerAndSerialNumber.getSerialNumber()  );
			verify(messageDigest, contentType, cert.getPublicKey());
		} else {
            assert(
						  signerIdentifier.getType().equals(SignerIdentifier.SUBJECT_KEY_IDENTIFIER) );

			// XXX Do we have method to get key using keyIdentifier
		}
    }
    

    /**
     * Verifies that this SignerInfo contains a valid signature of the
     * given message digest.  If any signed attributes are present,
     * they are also validated. The verification algorithm is as follows:<ul>
     *
     * <li>If no signed attributes are present, the content type is 
     *  verified to be <i>data</i>. Then it is verified that the message
     *  digest passed
     *  in, when encrypted with the given public key, matches the encrypted
     *  digest in the SignerInfo.
     *
     * <li>If signed attributes are present,
     *  two particular attributes must be present: <ul>
     *  <li>PKCS #9 Content-Type, the type of content that is being signed.
     *      This must match the contentType parameter.
     *  <li>PKCS #9 Message-Digest, the digest of the content that is being
     *      signed. This must match the messageDigest parameter.
     * </ul>
     * After these two attributes are verified to be both present and correct,
     * the encryptedDigest field of the SignerInfo is verified to be the
     * signature of the contents octets of the DER encoding of the
     * signedAttributes field.
     *
     * </ul>
     *
     * @param messageDigest The hash of the content that is signed by this
     *  SignerInfo.
     * @param contentType The type of the content that is signed by this
     *  SignerInfo.
     * @param pubkey The public key to use to verify the signature.
     */
    public void verify(byte[] messageDigest, OBJECT_IDENTIFIER contentType,
        PublicKey pubkey)
        throws NotInitializedException, NoSuchAlgorithmException,
        InvalidKeyException, TokenException, SignatureException
    {

        if( signedAttributes == null ) {
            verifyWithoutSignedAttributes(messageDigest, contentType,
                pubkey);
        } else {
            verifyWithSignedAttributes(messageDigest, contentType,
                pubkey);
        }
    }

    /**
     * Verifies that the message digest passed in, when encrypted with the
     * given public key, matches the encrypted digest in the SignerInfo.
     */
    private void verifyWithoutSignedAttributes
        (byte[] messageDigest, OBJECT_IDENTIFIER contentType,
        PublicKey pubkey)
        throws NotInitializedException, NoSuchAlgorithmException,
        InvalidKeyException, TokenException, SignatureException
    {
        if( ! contentType.equals(ContentInfo.DATA) ) {
            // only data can be signed this way.  Everything else has
            // to go into signedAttributes.
            throw new SignatureException(
                "Content-Type is not DATA, but there are"+
                " no signed attributes");
        }

        SignatureAlgorithm sigAlg =
            SignatureAlgorithm.fromOID(
                digestEncryptionAlgorithm.getOID()
            );

        CryptoToken token = CryptoManager.getInstance()
                .getInternalCryptoToken();
        Signature sig;
        byte[] toBeVerified;
        if (sigAlg.getRawAlg() == SignatureAlgorithm.RSASignature) {
            // create DigestInfo structure
            SEQUENCE digestInfo = createDigestInfo(messageDigest, false);
            toBeVerified = ASN1Util.encode(digestInfo);
            sig = token.getSignatureContext(sigAlg.getRawAlg());
        } else {
            toBeVerified = messageDigest;
            sig = token.getSignatureContext(sigAlg);
        }
        
        sig.initVerify(pubkey);
        sig.update(toBeVerified);
        if( sig.verify(encryptedDigest.toByteArray()) ) {
            return; // success
        } else {
            throw new SignatureException(
                "Encrypted message digest parameter does not "+
                "match encrypted digest in SignerInfo");
        }
    }


    /**
     * Verifies a SignerInfo with signed attributes.  If signed
     * attributes are present, then two particular attributes must
     * be present: <ul>
     * <li>PKCS #9 Content-Type, the type of content that is being signed.
     *      This must match the contentType parameter.
     * <li>PKCS #9 Message-Digest, the digest of the content that is being
     *      signed. This must match the messageDigest parameter.
     * </ul>
     * After these two attributes are verified to be both present and correct,
     * the encryptedDigest field of the SignerInfo is verified to be the
     * signature of the contents octets of the DER encoding of the
     * signedAttributes field.
     */
    private void verifyWithSignedAttributes
        (byte[] messageDigest, OBJECT_IDENTIFIER contentType,
        PublicKey pubkey)
        throws NotInitializedException, NoSuchAlgorithmException,
        InvalidKeyException, TokenException, SignatureException
    {

        int numAttrib = signedAttributes.size();

        if(numAttrib < 2) {
            throw new SignatureException(
                "At least two signed attributes must be present:"+
                " content-type and message-digest");
        }

        // go through the signed attributes, verifying the
        // interesting ones
        boolean foundContentType = false;
        boolean foundMessageDigest = false;
        for( int i = 0; i < numAttrib; i++ ) {

            if( ! (signedAttributes.elementAt(i) instanceof Attribute)) {
                throw new SignatureException(
                    "Element of signedAttributes is not an Attribute");
            }

            Attribute attrib = (Attribute)
                    signedAttributes.elementAt(i);

            if( attrib.getType().equals(CONTENT_TYPE) ) {
                // content-type.  Compare with what was passed in.

                SET vals = attrib.getValues();
                if( vals.size() != 1 ) {
                    throw new SignatureException(
                        "Content-Type attribute "+
                        " does not have exactly one value");
                }

                ASN1Value val = vals.elementAt(0);
                OBJECT_IDENTIFIER ctype;
                try {
                    if( val instanceof OBJECT_IDENTIFIER ) {
                        ctype = (OBJECT_IDENTIFIER) val;
                    } else if( val instanceof ANY ) {
                        ctype = (OBJECT_IDENTIFIER) ((ANY)val).decodeWith(
                                    OBJECT_IDENTIFIER.getTemplate() );
                    } else {
                        // what the heck is it? not what it's supposed to be
                        throw new InvalidBERException(
                        "Content-Type signed attribute has unexpected"+
                        " content type");
                    }
                } catch( InvalidBERException e ) {
                    throw new SignatureException(
                        "Content-Type signed attribute does not have "+
                        "OBJECT IDENTIFIER value");
                }

                // compare the content type in the attribute to the
                // contentType parameter
                if( ! ctype.equals( contentType ) ) {
                    throw new SignatureException(
                        "Content-type in signed attributes does not "+
                        "match content-type being verified");
                }

                // content type is A-OK
                foundContentType = true;

            } else if( attrib.getType().equals(MESSAGE_DIGEST) ) {

                SET vals = attrib.getValues();
                if( vals.size() != 1 ) {
                    throw new SignatureException(
                        "Message-digest attribute does not have"+
                        " exactly one value");
                }

                ASN1Value val = vals.elementAt(0);
                byte[] mdigest;
                try {
                    if( val instanceof OCTET_STRING ) {
                        mdigest = ((OCTET_STRING)val).toByteArray();
                    } else if( val instanceof ANY ) {
                        OCTET_STRING os;
                        os = (OCTET_STRING) ((ANY)val).decodeWith(
                            OCTET_STRING.getTemplate() );
                        mdigest = os.toByteArray();
                    } else {
                        // what the heck is it? not what it's supposed to be
                        throw new InvalidBERException(
                        "Content-Type signed attribute has unexpected"+
                        " content type");
                    }
                } catch( InvalidBERException e ) {
                    throw new SignatureException(
                        "Message-digest attribute does not"+
                        " have OCTET STRING value");
                }

                // compare the message digest in the attribute to the
                // message digest being verified
                if( ! byteArraysAreSame(mdigest, messageDigest) ) {
                    throw new SignatureException(
                        "Message-digest attribute does not"+
                        " match message digest being verified");
                }

                // message digest is A-OK
                foundMessageDigest = true;
            }

            // we don't care about other attributes

        }

        if( !foundContentType ) {
            throw new SignatureException(
                "Signed attributes does not contain"+
                " PKCS #9 content-type attribute");
        }

        if( !foundMessageDigest ) {
            throw new SignatureException(
                "Signed attributes does not contain"+
                " PKCS #9 message-digest attribute");
        }

        SignatureAlgorithm sigAlg = SignatureAlgorithm.fromOID(
            digestEncryptionAlgorithm.getOID() );

        // All the signed attributes are present and correct.
        // Now verify the signature.
        CryptoToken token =
                    CryptoManager.getInstance().getInternalCryptoToken();
        Signature sig;

        // verify the contents octets of the DER encoded signed attribs
        byte[] encoding = ASN1Util.encode(signedAttributes);
        byte[] toBeVerified;
        if (sigAlg.getRawAlg() == SignatureAlgorithm.RSASignature) {
            // create DigestInfo structure
            SEQUENCE digestInfo = createDigestInfo(encoding, true);
            toBeVerified = ASN1Util.encode(digestInfo);
            sig = token.getSignatureContext(SignatureAlgorithm.RSASignature);
        } else {
            toBeVerified = encoding;
            sig = token.getSignatureContext(sigAlg);
        }
 
        sig.initVerify(pubkey);
        sig.update( toBeVerified );

        if( ! sig.verify(encryptedDigest.toByteArray()) ) {
            // signature is invalid
            throw new SignatureException("encryptedDigest was not the correct"+
                " signature of the contents octets of the DER-encoded"+
                " signed attributes");
        }

        // SUCCESSFULLY VERIFIED

    }
        
    private SEQUENCE createDigestInfo(byte[] data, boolean doDigest) throws NoSuchAlgorithmException {
        if(data == null || data.length == 0){
            throw new IllegalArgumentException("Data to digest must be supplied");
        }
        SEQUENCE digestInfo = new SEQUENCE();
        digestInfo.addElement(this.digestAlgorithm);
        byte[] digest;
        if (doDigest) {
            MessageDigest md = MessageDigest.getInstance(
                    DigestAlgorithm.fromOID(this.digestAlgorithm.getOID()).toString());
            digest = md.digest(data);
        } else {
            digest = data;
        }
        digestInfo.addElement(new OCTET_STRING(digest));
        return digestInfo;
    }


    /**
     * Compares two non-null byte arrays.  Returns true if they are identical,
     * false otherwise.
     */
    private static boolean byteArraysAreSame(byte[] left, byte[] right) {

        assert(left!=null && right!=null);

        if( left.length != right.length ) {
            return false;
        }

        for(int i = 0 ; i < left.length ; i++ ) {
            if( left[i] != right[i] ) {
                return false;
            }
        }

        return true;
    } 

    ///////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////
    // DER-encoding
    ///////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////

    private static final Tag TAG = SEQUENCE.TAG;
    public Tag getTag() {
        return TAG;
    }

    public void encode(OutputStream ostream) throws IOException {
        encode(getTag(),ostream);
    }

    public void encode(Tag tag, OutputStream ostream) throws IOException {
        SEQUENCE sequence = new SEQUENCE();

        sequence.addElement( version );
        sequence.addElement( signerIdentifier );
        sequence.addElement( digestAlgorithm );
        if( signedAttributes != null ) {
            sequence.addElement( new Tag(0), signedAttributes );
        }
        sequence.addElement( digestEncryptionAlgorithm );
        sequence.addElement( encryptedDigest );
        if( unsignedAttributes != null ) {
            sequence.addElement( new Tag(1), unsignedAttributes );
        }

        sequence.encode(tag,ostream);
    }

    public static Template getTemplate() {
        return templateInstance;
    }
    private static Template templateInstance = new Template();

    /**
     * A template for decoding a SignerInfo blob
     *
     */
    public static class Template implements ASN1Template {

        SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();

            // serial number
            seqt.addElement(INTEGER.getTemplate()); // vn

            // issuerAndSerialNumber
            seqt.addElement(SignerIdentifier.getTemplate()); // signerId

            // digestAlgorithm
            seqt.addElement(AlgorithmIdentifier.getTemplate()); // digest alg

            // signedAttributes
            seqt.addOptionalElement(
                        new Tag(0),
                        new SET.OF_Template(Attribute.getTemplate()));
          
            // digestEncryptionAlgorithm
            seqt.addElement(AlgorithmIdentifier.getTemplate());  // dig encr alg

            // encryptedDigest
            seqt.addElement(OCTET_STRING.getTemplate()); // encr digest

            // unsigned attributes
            seqt.addOptionalElement(
                    new Tag(1),
                    new SET.OF_Template(Attribute.getTemplate()));

        }
        
        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        public ASN1Value decode(InputStream istream) 
            throws IOException, InvalidBERException
            {
                return decode(TAG,istream);
            }

        public ASN1Value decode(Tag implicitTag, InputStream istream)
            throws IOException, InvalidBERException
            {
                SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag,istream);
                assert(seq.size() == 7);

                return new SignerInfo(
                    (INTEGER)                   seq.elementAt(0),
                    (SignerIdentifier)     seq.elementAt(1),
                    (AlgorithmIdentifier)       seq.elementAt(2),
                    (SET)                       seq.elementAt(3),
                    (AlgorithmIdentifier)       seq.elementAt(4),
                    ((OCTET_STRING)             seq.elementAt(5)).toByteArray(),
                    (SET)                       seq.elementAt(6)
                    );
            }
    } // end of template

}
