/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs7;

import java.io.CharConversionException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.spec.RC2ParameterSpec;

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
import org.mozilla.jss.crypto.HMACAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.IllegalBlockSizeException;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyGenerator;
import org.mozilla.jss.crypto.PBEAlgorithm;
import org.mozilla.jss.crypto.PBEKeyGenParams;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.pkcs12.PasswordConverter;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.primitive.PBEParameter;
import org.mozilla.jss.pkix.primitive.PBES2Params;
import org.mozilla.jss.pkix.primitive.PBKDF2Params;
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
     * @param pbeAlg The algorithm for generating a symmetric key from
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
    createPBE(PBEAlgorithm pbeAlg, Password password, byte[] salt,
            int iterationCount,
            KeyGenerator.CharToByteConverter charToByteConverter,
            byte[] toBeEncrypted)
        throws NotInitializedException, NoSuchAlgorithmException,
        InvalidKeyException, InvalidAlgorithmParameterException, TokenException,
        CharConversionException
    {

      try {
        CryptoManager cman = CryptoManager.getInstance();

        // generate key
        CryptoToken token = cman.getInternalCryptoToken();
        KeyGenerator kg = token.getKeyGenerator( pbeAlg );
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
        Class<?> [] paramClasses = encAlg.getParameterClasses();
        for (int i = 0; i < paramClasses.length; i ++) {
            if ( paramClasses[i].equals(
                      javax.crypto.spec.IvParameterSpec.class ) ) {
                params = new IVParameterSpec(kg.generatePBE_IV());
                break;
            } else if ( paramClasses[i].equals( RC2ParameterSpec.class ) ) {
                params = new RC2ParameterSpec(key.getStrength(),
                                              kg.generatePBE_IV());
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
                pbeAlg.toOID(), pbeParam);

        // create EncryptedContentInfo
        return new EncryptedContentInfo(
                ContentInfo.DATA,
                encAlgID,
                new OCTET_STRING(encrypted) );


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
        KeyGenAlgorithm kgAlg = KeyGenAlgorithm.fromOID( contentEncryptionAlgorithm.getOID() );
        if( !(kgAlg instanceof PBEAlgorithm) ) {
            throw new NoSuchAlgorithmException("KeyGenAlgorithm is not a"+
                " PBE algorithm");
        }
        ASN1Value params = contentEncryptionAlgorithm.getParameters();
        if( params == null ) {
            throw new InvalidAlgorithmParameterException(
                "PBE algorithms require parameters");
        }
        byte[] salt = null;
        int iterations = 0;
        EncryptionAlgorithm encAlg = null;
        AlgorithmParameterSpec algParams = null;
        HMACAlgorithm hashAlg = null;
        KeyGenerator.CharToByteConverter passwordConverter = charToByteConverter;
        if(!kgAlg.toOID().equals(PBEAlgorithm.PBE_PKCS5_PBES2.toOID())) {
            PBEParameter pbeParams;
            if( params instanceof PBEParameter) {
                pbeParams = (PBEParameter) params;
            } else {
                byte[] encodedParams = ASN1Util.encode(params);
                pbeParams = (PBEParameter)
                    ASN1Util.decode( PBEParameter.getTemplate(), encodedParams );
            }
            salt = pbeParams.getSalt();
            iterations = pbeParams.getIterations();
            encAlg = ((PBEAlgorithm)kgAlg).getEncryptionAlg();
            if(passwordConverter == null)
                passwordConverter = new PasswordConverter();
        }
        else {
            byte[] encodedParams = ASN1Util.encode(params);
            PBES2Params pbe2Params = (PBES2Params)
                    ASN1Util.decode( PBES2Params.getTemplate(), encodedParams);
            AlgorithmIdentifier keyDerivationFunc = pbe2Params.getKeyDerivationFunc();
            AlgorithmIdentifier encryptionScheme = pbe2Params.getEncryptionScheme();
            if(!keyDerivationFunc.getOID().equals(PBEAlgorithm.PBE_PKCS5_PBKDF2.toOID())) {
                throw new InvalidAlgorithmParameterException("PBEs2 requires a PBKDF2 keyDerivationFunc"
                    + keyDerivationFunc.getOID().toDottedString());
            }
            byte[] encodedPBKParams = ASN1Util.encode(keyDerivationFunc.getParameters());
            PBKDF2Params pbkParams = (PBKDF2Params) ASN1Util.decode(
                    PBKDF2Params.getTemplate(), encodedPBKParams);
            salt = pbkParams.getSalt();
            iterations = pbkParams.getIterations();

            encAlg = EncryptionAlgorithm.fromOID(encryptionScheme.getOID());
            hashAlg = HMACAlgorithm.fromOID(pbkParams.getPrf().getOID());
            OCTET_STRING iv = (OCTET_STRING) ASN1Util.decode(OCTET_STRING.getTemplate(), ASN1Util.encode(encryptionScheme.getParameters()));
            algParams = new IVParameterSpec(iv.toByteArray());
        }


        PBEKeyGenParams kgp = new PBEKeyGenParams(pass.getChars(),
                    salt, iterations, encAlg, hashAlg);
        try {
            // compute the key and IV
            CryptoToken token =
                CryptoManager.getInstance().getInternalCryptoToken();
            KeyGenerator kg = token.getKeyGenerator( kgAlg );
            if( passwordConverter != null ) {
                kg.setCharToByteConverter( passwordConverter );
            }
            kg.initialize( kgp );
            SymmetricKey key = kg.generate();

            // compute algorithm parameters
            if(algParams == null) {
                Class<?> [] paramClasses = encAlg.getParameterClasses();
                for (int i = 0; i < paramClasses.length; i ++) {
                    if ( paramClasses[i].equals(
                              javax.crypto.spec.IvParameterSpec.class ) ) {
                        algParams = new IVParameterSpec( kg.generatePBE_IV() );
                        break;
                    } else if ( paramClasses[i].equals(RC2ParameterSpec.class ) ) {
                        algParams = new RC2ParameterSpec(key.getStrength(),
                                                         kg.generatePBE_IV());
                        break;
                    }
                }
            }
            // perform the decryption
            Cipher cipher = token.getCipherContext( encAlg );
            cipher.initDecrypt(key, algParams);

            byte[] ec = encryptedContent.toByteArray();
            return cipher.doFinal( ec );

        } finally {
            kgp.clear();
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
        encode(getTag(),ostream);
    }

    @Override
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

        @Override
        public boolean tagMatch(Tag tag) {
            return (tag.equals(EncryptedContentInfo.TAG));
        }

        @Override
        public ASN1Value decode(InputStream istream)
            throws IOException, InvalidBERException
            {
                return decode(TAG,istream);
            }

        @Override
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
