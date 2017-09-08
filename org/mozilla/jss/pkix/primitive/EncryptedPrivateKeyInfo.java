/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkix.primitive;

import org.mozilla.jss.asn1.*;
import java.io.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.util.Assert;
import java.security.*;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.util.Password;
import org.mozilla.jss.crypto.PrivateKey;
import java.security.spec.AlgorithmParameterSpec;

/**
 * PKCS #8 <i>EncryptedPrivateKeyInfo</i>.
 * <pre>
 * EncryptedPrivateKeyInfo ::= SEQUENCE {
 *      encryptionAlgorithm     AlgorithmIdentifier,
 *      encryptedData           OCTET STRING }
 * </pre>
 */
public class EncryptedPrivateKeyInfo implements ASN1Value {

    ///////////////////////////////////////////////////////////////////////
    // members and member access
    ///////////////////////////////////////////////////////////////////////
    private AlgorithmIdentifier encryptionAlgorithm;
    private OCTET_STRING encryptedData;
    private SEQUENCE sequence;

    public AlgorithmIdentifier getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    public OCTET_STRING getEncryptedData() {
        return encryptedData;
    }

    ///////////////////////////////////////////////////////////////////////
    // Constructors
    ///////////////////////////////////////////////////////////////////////

    private EncryptedPrivateKeyInfo() { }

    /**
     * Creates an EncryptedPrivateKeyInfo from its components.
     *
     */
    public EncryptedPrivateKeyInfo( AlgorithmIdentifier encryptionAlgorithm,
                OCTET_STRING encryptedData)
    {
        if( encryptionAlgorithm==null || encryptedData==null ) {
            throw new IllegalArgumentException(
                    "EncryptedPrivateKeyInfo parameter is null");
        }

        this.encryptionAlgorithm = encryptionAlgorithm;
        this.encryptedData = encryptedData;

        sequence = new SEQUENCE();
        sequence.addElement(encryptionAlgorithm);
        sequence.addElement(encryptedData);

    }

    ///////////////////////////////////////////////////////////////////////
    // crypto shortcuts
    ///////////////////////////////////////////////////////////////////////

    /**
     * Creates a new EncryptedPrivateKeyInfo, where the data is encrypted
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
     * @param pki The PrivateKeyInfo to be encrypted and stored in the
     *      EncryptedContentInfo. Before they are encrypted, they will be
     *      padded using PKCS padding.
     */
    public static EncryptedPrivateKeyInfo
    createPBE(PBEAlgorithm keyGenAlg, Password password, byte[] salt,
            int iterationCount,
            KeyGenerator.CharToByteConverter charToByteConverter,
            PrivateKeyInfo pki)
        throws CryptoManager.NotInitializedException, NoSuchAlgorithmException,
        InvalidKeyException, InvalidAlgorithmParameterException, TokenException,
        CharConversionException
    {
      try {

        // check key gen algorithm
        if( ! (keyGenAlg instanceof PBEAlgorithm) ) {
            throw new NoSuchAlgorithmException("Key generation algorithm"+
                " is not a PBE algorithm");
        }
        PBEAlgorithm pbeAlg = (PBEAlgorithm) keyGenAlg;

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
        if( encAlg.getParameterClass().equals( IVParameterSpec.class ) ) {
            params = new IVParameterSpec( kg.generatePBE_IV() );
        }

        // perform encryption
        Cipher cipher = token.getCipherContext( encAlg );
        cipher.initEncrypt( key, params );
        byte[] encrypted = cipher.doFinal( Cipher.pad(
                ASN1Util.encode(pki), encAlg.getBlockSize()) );

        // make encryption algorithm identifier
        PBEParameter pbeParam = new PBEParameter( salt, iterationCount );
        AlgorithmIdentifier encAlgID = new AlgorithmIdentifier(
                keyGenAlg.toOID(), pbeParam);

        // create EncryptedPrivateKeyInfo
        EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo (
                encAlgID,
                new OCTET_STRING(encrypted) );

        return epki;

      } catch( IllegalBlockSizeException e ) {
        Assert.notReached("IllegalBlockSizeException in EncryptedContentInfo"
            +".createPBE");
      } catch( BadPaddingException e ) {
        Assert.notReached("BadPaddingException in EncryptedContentInfo"
            +".createPBE");
      }
      return null;
    }


    /**
     * Export a private key in PBES2 format, using a random PBKDF2 salt.
     *
     * Token must support the CKM_PKCS5_PBKD2 mechanism.
     *
     * @param saltLen Length of salt in bytes (default: 16)
     * @param kdfIterations PBKDF2 iterations (default: 2000)
     * @param encAlg The symmetric encryption algorithm for enciphering the
     *               private key.  Determines the size of derived key.
     * @param pwd Password
     * @param charToByteConverter The mechanism for converting the characters
     *      in the password into bytes.  If null, the default mechanism
     *      will be used, which is UTF8.
     * @param privateKeyInfo The encoded PrivateKeyInfo to be encrypted and
     *                       stored in the EncryptedContentInfo.
     */
    public static EncryptedPrivateKeyInfo createPBES2(
            int saltLen,
            int kdfIterations,
            EncryptionAlgorithm encAlg,
            Password pwd,
            KeyGenerator.CharToByteConverter charToByteConverter,
            PrivateKeyInfo privateKeyInfo)
        throws CryptoManager.NotInitializedException, NoSuchAlgorithmException,
        InvalidKeyException, InvalidAlgorithmParameterException, TokenException,
        CharConversionException
    {
        if (encAlg == null)
            throw new IllegalArgumentException("encAlg cannot be null");
        if (pwd == null)
            throw new IllegalArgumentException("pwd cannot be null");
        if (privateKeyInfo == null)
            throw new IllegalArgumentException("privateKeyInfo cannot be null");

        if (kdfIterations < 1)
            kdfIterations = 2000;
        if (saltLen < 1)
            saltLen = 16;

        try {
            // generate random PBKDF2 salt
            SecureRandom random = new SecureRandom();
            byte salt[] = new byte[saltLen];
            random.nextBytes(salt);

            // derive symmetric key from passphrase using PBKDF2
            CryptoManager cm = CryptoManager.getInstance();
            CryptoToken token = cm.getInternalCryptoToken();
            KeyGenerator kg = token.getKeyGenerator(
                PBEAlgorithm.PBE_PKCS5_PBKDF2);
            PBEKeyGenParams pbekgParams = new PBEKeyGenParams(
                pwd.getChars(), salt, kdfIterations, encAlg);
            if (charToByteConverter != null)
                kg.setCharToByteConverter(charToByteConverter);
            kg.initialize(pbekgParams);
            SymmetricKey sk = kg.generate();

            // encrypt PrivateKeyInfo
            byte iv[] = new byte[encAlg.getBlockSize()];
            random.nextBytes(iv);
            Cipher cipher = token.getCipherContext(encAlg);
            cipher.initEncrypt(sk, new IVParameterSpec(iv));
            byte[] encData = cipher.doFinal(ASN1Util.encode(privateKeyInfo));

            // construct KDF AlgorithmIdentifier
            SEQUENCE paramsKdf = new SEQUENCE();
            paramsKdf.addElement(new OCTET_STRING(salt));
            paramsKdf.addElement(new INTEGER((long) kdfIterations));
            paramsKdf.addElement(new INTEGER((long) sk.getLength()));
            AlgorithmIdentifier algIdKdf = new AlgorithmIdentifier(
                PBEAlgorithm.PBE_PKCS5_PBKDF2.toOID(), paramsKdf);

            // construct encryption AlgorithmIdentifier
            AlgorithmIdentifier algIdEnc = new AlgorithmIdentifier(
                encAlg.toOID(), new OCTET_STRING(iv));

            // construct "composite" PBES2 AlgorithmIdentifier
            SEQUENCE paramsPBES2 = new SEQUENCE();
            paramsPBES2.addElement(algIdKdf);
            paramsPBES2.addElement(algIdEnc);
            AlgorithmIdentifier algIdPBES2 = new AlgorithmIdentifier(
                PBEAlgorithm.PBE_PKCS5_PBES2.toOID(), paramsPBES2);

            // construct EncryptedPrivateKeyInfo
            return new EncryptedPrivateKeyInfo(algIdPBES2, new OCTET_STRING(encData));
        } catch (IllegalBlockSizeException e) {
            Assert.notReached("IllegalBlockSizeException in EncryptedContentInfo.createPBES2");
        } catch (BadPaddingException e) {
            Assert.notReached("BadPaddingException in EncryptedContentInfo.createPBES2");
        }
        return null; // unreachable
    }


    /**
     * Creates a new EncryptedPrivateKeyInfo, where the data is encrypted
     * with a password-based key- 
     *       with wrapping/unwrapping happening on token.
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
     * @param pri The PrivateKey to be encrypted and stored in the
     *      EncryptedContentInfo.
     */
    public static EncryptedPrivateKeyInfo
    createPBE(PBEAlgorithm keyGenAlg, Password password, byte[] salt,
            int iterationCount,
            KeyGenerator.CharToByteConverter charToByteConverter,
            PrivateKey pri, CryptoToken token)
        throws CryptoManager.NotInitializedException, NoSuchAlgorithmException,
        InvalidKeyException, InvalidAlgorithmParameterException, TokenException,
        CharConversionException
    {
      try {

        // check key gen algorithm

        if( ! (keyGenAlg instanceof PBEAlgorithm) ) {
            throw new NoSuchAlgorithmException("Key generation algorithm"+
                " is not a PBE algorithm");
        }

        PBEAlgorithm pbeAlg = (PBEAlgorithm) keyGenAlg;

        // generate key

        KeyGenerator kg = token.getKeyGenerator( keyGenAlg );
        PBEKeyGenParams pbekgParams = new PBEKeyGenParams(
            password, salt, iterationCount);
        if( charToByteConverter != null ) {
            kg.setCharToByteConverter( charToByteConverter );
        }
        kg.initialize(pbekgParams);
        kg.temporaryKeys(true);
        SymmetricKey key = kg.generate();

        // generate IV
        EncryptionAlgorithm encAlg = pbeAlg.getEncryptionAlg();
        AlgorithmParameterSpec params=null;
        if( encAlg.getParameterClass().equals( IVParameterSpec.class ) ) {
            params = new IVParameterSpec( kg.generatePBE_IV() );
        }

        KeyWrapper wrapper = token.getKeyWrapper(
                KeyWrapAlgorithm.DES3_CBC_PAD);
        wrapper.initWrap(key, params);
        byte encrypted[] = wrapper.wrap(pri);

        // make encryption algorithm identifier
        PBEParameter pbeParam = new PBEParameter( salt, iterationCount );
        AlgorithmIdentifier encAlgID = new AlgorithmIdentifier(
                keyGenAlg.toOID(), pbeParam);

        // create EncryptedPrivateKeyInfo
        EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo (
                encAlgID,
                new OCTET_STRING(encrypted) );

        return epki;

      } catch (Exception e) {
        System.out.println("createPBE: exception:"+e.toString());
        Assert.notReached("EncryptedPrivateKeyInfo exception:"
            +".createPBE");
      }

      return null;
    }


    /**
     * Decrypts an EncryptedPrivateKeyInfo that was encrypted with a PBE
     *  algorithm.  The algorithm and its parameters are extracted from
     *  the EncryptedPrivateKeyInfo.
     *
     * @param pass The password to use to generate the PBE key.
     * @param charToByteConverter The converter to change the password
     *      characters to bytes.  If null, the default conversion is used.
     */
    public PrivateKeyInfo
    decrypt(Password pass, KeyGenerator.CharToByteConverter charToByteConverter)
        throws CryptoManager.NotInitializedException, NoSuchAlgorithmException,
        InvalidBERException, InvalidKeyException,
        InvalidAlgorithmParameterException, TokenException,
        IllegalBlockSizeException, BadPaddingException, CharConversionException
    {
        // get the key gen parameters
        AlgorithmIdentifier algid = encryptionAlgorithm;
        KeyGenAlgorithm kgAlg = KeyGenAlgorithm.fromOID(algid.getOID());
        if( !(kgAlg instanceof PBEAlgorithm)) {
            throw new NoSuchAlgorithmException("KeyGenAlgorithm is not a "+
                "PBE algorithm");
        }
        ASN1Value params = algid.getParameters();
        if( params == null ) {
            throw new InvalidAlgorithmParameterException(
                "PBE algorithms require parameters");
        }
        PBEParameter pbeParams;
        if( params instanceof PBEParameter ) {
            pbeParams = (PBEParameter) params;
        } else {
            byte[] encodedParams = ASN1Util.encode(params);
            pbeParams = (PBEParameter)
                ASN1Util.decode(PBEParameter.getTemplate(), encodedParams);
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
        kg.initialize(kgp);
        SymmetricKey key = kg.generate();

        // compute algorithm parameters
        EncryptionAlgorithm encAlg = ((PBEAlgorithm)kgAlg).getEncryptionAlg();
        AlgorithmParameterSpec algParams;
        if( encAlg.getParameterClass().equals( IVParameterSpec.class ) ) {
            algParams = new IVParameterSpec( kg.generatePBE_IV() );
        } else {
            algParams = null;
        }

        // perform the decryption
        Cipher cipher = token.getCipherContext( encAlg );
        cipher.initDecrypt(key, algParams);
        byte[] decrypted = Cipher.unPad( cipher.doFinal(
                                            encryptedData.toByteArray() ) );

        return (PrivateKeyInfo)
            ASN1Util.decode(PrivateKeyInfo.getTemplate(), decrypted);

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
     * A template class for decoding EncryptedPrivateKeyInfos from BER.
     */
    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();

            seqt.addElement( AlgorithmIdentifier.getTemplate() );
            seqt.addElement( OCTET_STRING.getTemplate() );
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

            return new EncryptedPrivateKeyInfo(
                    (AlgorithmIdentifier) seq.elementAt(0),
                    (OCTET_STRING) seq.elementAt(1) );
        }
    }
}
