/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.pkix.cms;

import java.io.CharConversionException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.EXPLICIT;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;
import org.mozilla.jss.crypto.Cipher;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.IllegalBlockSizeException;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyGenerator;
import org.mozilla.jss.crypto.PBEAlgorithm;
import org.mozilla.jss.crypto.PBEKeyGenParams;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.primitive.PBEParameter;
import org.mozilla.jss.util.Assert;
import org.mozilla.jss.util.Password;

/**
 * The PKCS #7 type <i>EncryptedContentInfo</i>, which encapsulates
 * encrypted data.
 */
public class EncryptedContentInfo implements ASN1Value {

    ///////////////////////////////////////////////////////////////////////
    // members and member access
    ///////////////////////////////////////////////////////////////////////
    private OBJECT_IDENTIFIER    contentType;
    private AlgorithmIdentifier  contentEncryptionAlgorithm;
    private OCTET_STRING         encryptedContent; // may be null

    private SEQUENCE sequence = new SEQUENCE();

    public OBJECT_IDENTIFIER getContentType() {
        return contentType;
    }

    public AlgorithmIdentifier getContentEncryptionAlgorithm() {
        return contentEncryptionAlgorithm;
    }

    public OCTET_STRING getEncryptedContent() {
        return encryptedContent;
    }

    public boolean hasEncryptedContent() {
        return (encryptedContent!=null);
    }

    ///////////////////////////////////////////////////////////////////////
    // Constructors
    ///////////////////////////////////////////////////////////////////////

    /**
     * Create a EnvelopedData ASN1 object.
     */
    public EncryptedContentInfo(
                OBJECT_IDENTIFIER contentType,
                AlgorithmIdentifier contentEncryptionAlgorithm,
                OCTET_STRING encryptedContent)
        {
			this(contentType,
								 contentEncryptionAlgorithm,
								 encryptedContent,
								 false);

    }

    public EncryptedContentInfo(
				 OBJECT_IDENTIFIER contentType,
				 AlgorithmIdentifier contentEncryptionAlgorithm,
				 OCTET_STRING encryptedContent,
                 boolean createHackedCRSCompatibleECI)
	{
        this.contentType = contentType;
        this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
        this.encryptedContent = encryptedContent;

        sequence.addElement(contentType);
        sequence.addElement(contentEncryptionAlgorithm);
        if(encryptedContent != null) {
			if (createHackedCRSCompatibleECI) {
				sequence.addElement(new EXPLICIT(new Tag(0), encryptedContent));
			}
			else {
				sequence.addElement(new Tag(0), encryptedContent);
			}
        }
	}

	public static EncryptedContentInfo createCRSCompatibleEncryptedContentInfo(OBJECT_IDENTIFIER contentType,
				 AlgorithmIdentifier contentEncryptionAlgorithm,
				 OCTET_STRING encryptedContent)
	{
		return new EncryptedContentInfo(contentType,
										contentEncryptionAlgorithm,
										encryptedContent,
										true);
	}


    ///////////////////////////////////////////////////////////////////////
    // Crypto shortcuts
    ///////////////////////////////////////////////////////////////////////

    /**
     * Creates a new EncryptedContentInfo, where the data is encrypted
     * with a password-based key.
     *
     * @param keyGenAlg The algorithm for generating a symmetric key from
     *      a password, salt, and iteration count.
     * @param password The password to use in generating the key.
     * @param salt The salt to use in generating the key.
     * @param iterationCount The number of hashing iterations to perform
     *      while generating the key.
     * @param charToByteConverter The mechanism for converting the characters
     *      in the password into bytes.  If null, the default mechanism
     *      will be used, which is UTF8.
     * @param toBeEncrypted The bytes to be encrypted and stored in the
     *      EncryptedContentInfo. Before they are encrypted, they will be
     *      padded using PKCS padding.
     */
    public static EncryptedContentInfo
    createPBE(PBEAlgorithm keyGenAlg, Password password, byte[] salt,
            int iterationCount,
            KeyGenerator.CharToByteConverter charToByteConverter,
            byte[] toBeEncrypted)
        throws NotInitializedException, NoSuchAlgorithmException,
        InvalidKeyException, InvalidAlgorithmParameterException, TokenException,
        CharConversionException
    {

      try {

        // check key gen algorithm
        if( ! (keyGenAlg instanceof PBEAlgorithm) ) {
            throw new NoSuchAlgorithmException("Key generation algorithm"+
                " is not a PBE algorithm");
        }
        PBEAlgorithm pbeAlg = keyGenAlg;

        CryptoManager cman = CryptoManager.getInstance();

        // generate key
        CryptoToken token = cman.getInternalCryptoToken();
        KeyGenerator kg = token.getKeyGenerator( keyGenAlg );
        PBEKeyGenParams pbekgParams = new PBEKeyGenParams(
            password, salt, iterationCount);
        if( charToByteConverter != null ) {
            kg.setCharToByteConverter( charToByteConverter );
        }
        kg.initialize(pbekgParams);
        SymmetricKey key = kg.generate();

        // generate IV
        EncryptionAlgorithm encAlg = pbeAlg.getEncryptionAlg();
        AlgorithmParameterSpec params=null;
        Class<?> [] paramClasses = pbeAlg.getParameterClasses();
        for (int i = 0; i < paramClasses.length; i ++) {
            if ( paramClasses[i].equals( IVParameterSpec.class ) ) {
                params = new IVParameterSpec( kg.generatePBE_IV() );
                break;
            }
        }

        // perform encryption
        Cipher cipher = token.getCipherContext( encAlg );
        cipher.initEncrypt( key, params );
        byte[] encrypted = cipher.doFinal( Cipher.pad(
                toBeEncrypted, encAlg.getBlockSize()) );

        // make encryption algorithm identifier
        PBEParameter pbeParam = new PBEParameter( salt, iterationCount );
        AlgorithmIdentifier encAlgID = new AlgorithmIdentifier(
                keyGenAlg.toOID(), pbeParam);

        // create EncryptedContentInfo
        EncryptedContentInfo encCI = new EncryptedContentInfo(
                ContentInfo.DATA,
                encAlgID,
                new OCTET_STRING(encrypted) );

        return encCI;

      } catch( IllegalBlockSizeException e ) {
          throw new RuntimeException("IllegalBlockSizeException in EncryptedContentInfo"
            +".createPBE: " + e.getMessage(), e);
      } catch( BadPaddingException e ) {
          throw new RuntimeException("BadPaddingException in EncryptedContentInfo"
            +".createPBE: " + e.getMessage(), e);
      }
    }

    /**
     * Decrypts the content of an EncryptedContentInfo encrypted with a
     * PBE key.
     *
     * @param pass The password to use in generating the PBE decryption key.
     * @param charToByteConverter The converter for converting the password
     *      characters into bytes.  May be null to use the default.
     * @return The decrypted contents of the EncryptedContentInfo. The contents
     *      are first unpadded using the PKCS padding mechanism.
     */
    public byte[]
    decrypt(Password pass, KeyGenerator.CharToByteConverter charToByteConverter)
        throws IllegalStateException,NotInitializedException,
        NoSuchAlgorithmException, InvalidBERException, IOException,
        InvalidKeyException, InvalidAlgorithmParameterException, TokenException,
        IllegalBlockSizeException, BadPaddingException
    {
        if( encryptedContent == null ) {
            return null;
        }

        // get the key gen parameters
        AlgorithmIdentifier algid = contentEncryptionAlgorithm;
        KeyGenAlgorithm kgAlg = KeyGenAlgorithm.fromOID( algid.getOID() );
        if( !(kgAlg instanceof PBEAlgorithm) ) {
            throw new NoSuchAlgorithmException("KeyGenAlgorithm is not a"+
                " PBE algorithm");
        }
        ASN1Value params = algid.getParameters();
        if( params == null ) {
            throw new InvalidAlgorithmParameterException(
                "PBE algorithms require parameters");
        }
        PBEParameter pbeParams;
        if( params instanceof PBEParameter) {
            pbeParams = (PBEParameter) params;
        } else {
            byte[] encodedParams = ASN1Util.encode(params);
            pbeParams = (PBEParameter)
                ASN1Util.decode( PBEParameter.getTemplate(), encodedParams );
        }
        PBEKeyGenParams kgp = new PBEKeyGenParams(pass,
                    pbeParams.getSalt(), pbeParams.getIterations() );


        // compute the key and IV
        CryptoToken token =
            CryptoManager.getInstance().getInternalCryptoToken();
        KeyGenerator kg = token.getKeyGenerator( kgAlg );
        if( charToByteConverter != null ) {
            kg.setCharToByteConverter( charToByteConverter );
        }
        kg.initialize( kgp );
        SymmetricKey key = kg.generate();

        // compute algorithm parameters
        EncryptionAlgorithm encAlg = ((PBEAlgorithm)kgAlg).getEncryptionAlg();
        AlgorithmParameterSpec algParams = null;
        Class<?> [] paramClasses = encAlg.getParameterClasses();
        for (int i = 0; i < paramClasses.length; i ++) {
            if ( paramClasses[i].equals(
                       javax.crypto.spec.IvParameterSpec.class ) ) {
                algParams = new IVParameterSpec( kg.generatePBE_IV() );
                break;
            }
        }

        // perform the decryption
        Cipher cipher = token.getCipherContext( encAlg );
        cipher.initDecrypt(key, algParams);
        return Cipher.unPad(cipher.doFinal( encryptedContent.toByteArray() ));
    }


    ///////////////////////////////////////////////////////////////////////
    // DER encoding
    ///////////////////////////////////////////////////////////////////////

    private static final Tag TAG = SEQUENCE.TAG;
    public Tag getTag() {
        return TAG;
    }

    public void encode(OutputStream ostream) throws IOException {
        encode(getTag(),ostream);
    }

    public void encode(Tag tag, OutputStream ostream) throws IOException {
        sequence.encode(tag,ostream);
    }

    public static Template getTemplate() {
        return templateInstance;
    }
    private static final Template templateInstance = new Template();

    /**
     * A template file for decoding a EnvelopedData blob
     *
     */

    public static class Template implements ASN1Template {

        public boolean tagMatch(Tag tag) {
            return (tag.equals(EncryptedContentInfo.TAG));
        }

        public ASN1Value decode(InputStream istream)
            throws IOException, InvalidBERException
            {
                return decode(TAG,istream);
            }

        public ASN1Value decode(Tag implicitTag, InputStream istream)
            throws IOException, InvalidBERException
            {
                SEQUENCE.Template seqt = new SEQUENCE.Template();
                seqt.addElement(new OBJECT_IDENTIFIER.Template());
                seqt.addElement(new AlgorithmIdentifier.Template());
                seqt.addOptionalElement(new Tag(0), new OCTET_STRING.Template());

                SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag,istream);
                assert(seq.size() ==3);

                return new EncryptedContentInfo(
                    (OBJECT_IDENTIFIER)   seq.elementAt(0),
                    (AlgorithmIdentifier) seq.elementAt(1),
                    (OCTET_STRING)        seq.elementAt(2)
                    );
            }
    } // end of template

}
