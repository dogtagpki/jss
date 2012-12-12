/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.provider.javax.crypto;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.*;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import org.mozilla.jss.crypto.KeyWrapper;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.TokenSupplierManager;
import org.mozilla.jss.crypto.Algorithm;
import org.mozilla.jss.crypto.SecretKeyFacade;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.SecretKeyFacade;
import org.mozilla.jss.crypto.TokenRuntimeException;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.util.Assert;

import org.mozilla.jss.pkcs11.PK11PubKey;
import org.mozilla.jss.pkcs11.PK11PrivKey;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.InvalidBERException;
import java.security.SecureRandom;

class JSSCipherSpi extends javax.crypto.CipherSpi {
    private String algFamily=null;
    private String algMode=null;
    private String algPadding=null;

    CryptoToken token = null;
    private org.mozilla.jss.crypto.Cipher cipher=null;
    private EncryptionAlgorithm encAlg = null;
    private org.mozilla.jss.crypto.KeyWrapper wrapper=null;
    private KeyWrapAlgorithm wrapAlg = null;
    private AlgorithmParameterSpec params = null;
    private int blockSize;
    //keyStrength  is used for RC2ParameterSpec and EncryptionAlgorithm.lookup
    private int keyStrength;  

    private JSSCipherSpi() { }

    protected JSSCipherSpi(String algFamily) {
        this.algFamily = algFamily;
        token = TokenSupplierManager.getTokenSupplier().getThreadToken();
    }

    public void engineSetMode(String mode) {
        this.algMode = mode;
    }

    public void engineSetPadding(String padding) {
        this.algPadding = padding;
    }

    static private SecretKey importKey(Key key)
         throws InvalidKeyException
    {
        if (key instanceof SecretKey) {
            SecretKey sKey = (SecretKey) key;
            SecretKeyFactory fact = null;
            try {
                fact = SecretKeyFactory.getInstance(sKey.getAlgorithm(),
                                                "Mozilla-JSS");
            } catch (NoSuchAlgorithmException e) {
                throw new InvalidKeyException(
                                  "Unable to translate key with Algorithm"
                                    + key.getAlgorithm());
            } catch (NoSuchProviderException ex) {
                throw new InvalidKeyException(
                    "Unable to find provider, this should not happen");
            }

            return fact.translateKey(sKey);
        }else {
            throw new InvalidKeyException("Invalid key type: " +
                                       key.getClass().getName());
        }
    }

    public void engineInit(int opmode, Key key,
        AlgorithmParameterSpec givenParams, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
      try {
        // throw away any previous state
        cipher = null;
        wrapper = null;

        params = givenParams;
        if( algFamily==null ) {
            throw new InvalidAlgorithmParameterException(
                "incorrectly specified algorithm");
        }
        if( opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE &&
            opmode != Cipher.WRAP_MODE && opmode != Cipher.UNWRAP_MODE )
        {
            throw new InvalidKeyException("Invalid opmode");
        }

        StringBuffer buf = new StringBuffer();
        buf.append(algFamily);
        if( algMode != null ) {
            buf.append('/');
            buf.append(algMode);
        }
        if( algPadding != null ) {
            buf.append('/');
            buf.append(algPadding);
        }

        if( opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.DECRYPT_MODE ) {
            if( ! (key instanceof SecretKeyFacade) )  {
                key = importKey(key);
            }
            SymmetricKey symkey = ((SecretKeyFacade)key).key;

            // lookup the encryption algorithm
            keyStrength = symkey.getStrength();
            encAlg = EncryptionAlgorithm.lookup(algFamily, algMode,
                algPadding, keyStrength);
            blockSize = encAlg.getBlockSize();

            if( !token.doesAlgorithm(encAlg) ) {
                throw new NoSuchAlgorithmException(
                    encAlg.toString() + " is not supported by this token " +
                    token.getName());
            }
            
            cipher = token.getCipherContext(encAlg);

            if( opmode == Cipher.ENCRYPT_MODE ) {
                if( params == noAlgParams ) {
                    // we're supposed to generate some params
                    params = generateAlgParams(encAlg, blockSize);
                }
                cipher.initEncrypt(symkey, params);
            } else if( opmode == Cipher.DECRYPT_MODE ) {
                if( params == noAlgParams) {
                    params = null;
                }
                cipher.initDecrypt(symkey, params);
            }
        } else {
            Assert._assert(
                opmode==Cipher.WRAP_MODE || opmode==Cipher.UNWRAP_MODE);
            wrapAlg = KeyWrapAlgorithm.fromString(buf.toString());
            blockSize = wrapAlg.getBlockSize();
            wrapper = token.getKeyWrapper(wrapAlg);

            // generate params if necessary
            if( params == noAlgParams ) {
                if( opmode == Cipher.WRAP_MODE ) {
                    params = generateAlgParams(wrapAlg, blockSize);
                } else {
                    Assert._assert(opmode == Cipher.UNWRAP_MODE);
                    params = null;
                }
            }

            if( key instanceof org.mozilla.jss.crypto.PrivateKey ) {
                if( opmode != Cipher.UNWRAP_MODE ) {
                    throw new InvalidKeyException(
                        "Private key can only be used for unwrapping");
                }
                wrapper.initUnwrap(
                    (org.mozilla.jss.crypto.PrivateKey) key, params );
            } else if( key instanceof PublicKey ) {
                if( opmode != Cipher.WRAP_MODE ) {
                    throw new InvalidKeyException(
                        "Public key can only be used for wrapping");
                }
                wrapper.initWrap((PublicKey) key, params);
            } else if( key instanceof org.mozilla.jss.crypto.SecretKeyFacade) {
                org.mozilla.jss.crypto.SecretKeyFacade sk =
                    (org.mozilla.jss.crypto.SecretKeyFacade) key;
                if( opmode == Cipher.WRAP_MODE ) {
                    wrapper.initWrap( sk.key, params );
                } else {
                    Assert._assert(opmode==Cipher.UNWRAP_MODE);
                    wrapper.initUnwrap( sk.key, params );
                }
            } else {
                throw new InvalidKeyException("Invalid key type: " +
                    key.getClass().getName());
            }
        }
      } catch (NoSuchAlgorithmException e) {
            throw new InvalidAlgorithmParameterException(e.getMessage());
      } catch(TokenException te) {
            throw new TokenRuntimeException(te.getMessage());
      }
    }

    public void engineInit(int opmode, Key key,
            AlgorithmParameters givenParams, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        try {
            AlgorithmParameterSpec gp = null;
            if (algFamily.compareToIgnoreCase("RC2") == 0) {
                gp = givenParams.getParameterSpec(                 
                    javax.crypto.spec.RC2ParameterSpec.class );
            } else if (algMode.compareToIgnoreCase("CBC") == 0) {
                 gp = givenParams.getParameterSpec(                 
                             javax.crypto.spec.IvParameterSpec.class );
            }            
            
            if (gp != null) { 
                engineInit(opmode, key, gp, random);
            } else {
                throw new InvalidAlgorithmParameterException("Unknown Parameter Spec");
            }
        } catch(Exception e) {
            throw new InvalidAlgorithmParameterException(e.getMessage());
        }
    }

    public void engineInit(int opmode, Key key, SecureRandom random)
        throws InvalidKeyException
    {
        try {
            engineInit(opmode, key, noAlgParams, random);
        } catch(InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException(e.getMessage());
        }
    }

    private AlgorithmParameterSpec
    generateAlgParams(Algorithm alg, int blockSize) throws InvalidKeyException {
        Class [] paramClasses = alg.getParameterClasses();
        AlgorithmParameterSpec  algParSpec = null;
        if( paramClasses == null ) {
            // no parameters are needed
            return null;
        } 
        // generate an IV
        byte[] iv = new byte[blockSize];  
        try {
            SecureRandom random = SecureRandom.getInstance("pkcs11prng", 
                                                       "Mozilla-JSS");
            random.nextBytes(iv);
        } catch (Exception e) {
            Assert.notReached(e.getMessage());
        }
        
        for (int i = 0; i < paramClasses.length; i ++) {
            if( paramClasses[i].equals( javax.crypto.spec.IvParameterSpec.class ) ) {
                algParSpec = new javax.crypto.spec.IvParameterSpec(iv);
                break;
            } else if ( paramClasses[i].equals( RC2ParameterSpec.class ) ) {
                algParSpec = new RC2ParameterSpec(keyStrength, iv);  
                break;
            }
        }

        return algParSpec;
    }

    private static class NoAlgParams implements AlgorithmParameterSpec { }
    private static final NoAlgParams noAlgParams = new NoAlgParams();

    public int engineGetBlockSize() {
        return blockSize;
    }

    public byte[] engineGetIV() {
        if( params == null ) {
            return null;
        }
        if( params instanceof IvParameterSpec) {
            return ((IvParameterSpec)params).getIV();
        } else if( params instanceof RC2ParameterSpec ) {
            return ((RC2ParameterSpec)params).getIV();
        } else {
            return null;
        }
    }

    public AlgorithmParameters engineGetParameters() {
        AlgorithmParameters algParams = null;
         try {
            if(( params instanceof IvParameterSpec ) 
               || ( params instanceof RC2ParameterSpec )) {
                algParams = AlgorithmParameters.getInstance(algFamily);
                algParams.init(params);
            }
          } catch(NoSuchAlgorithmException nsae) {
            Assert.notReached(nsae.getMessage());
          } catch(InvalidParameterSpecException ipse) {
            Assert.notReached(ipse.getMessage());
          }
        return algParams;
    }

    public int engineGetOutputSize(int inputLen) {
        int total = (blockSize-1) + inputLen;
        return ((total / blockSize) + 1) * blockSize;
    }

    public byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        if(cipher == null) {
            // Cipher is supposed to catch an illegal state, so we should never
            // get here
            Assert.notReached();
            return null;
        }
        try {
            return cipher.update(input, inputOffset, inputLen);
        } catch(TokenException te) {
            throw new TokenRuntimeException(te.getMessage());
        }
    }

    public int engineUpdate(byte[] input, int inputOffset, int inputLen,
        byte[] output, int outputOffset) throws ShortBufferException
    {
        byte[] bytes = engineUpdate(input, inputOffset, inputLen);
        if( bytes.length > output.length-outputOffset ) {
            throw new ShortBufferException(bytes.length +  " needed, " +
                (output.length-outputOffset) + " supplied");
        }
        System.arraycopy(bytes, 0, output, outputOffset, bytes.length);
        return bytes.length;
    }

    public byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
        throws IllegalBlockSizeException, BadPaddingException
    {
        if( cipher == null ) {
            // Cipher is supposed to catch an illegal state, so we should never
            // get here
            Assert.notReached();
            return null;
        }
        try {
            if( input == null || inputLen == 0) {
                return cipher.doFinal();
            } else {
                return cipher.doFinal(input, inputOffset, inputLen);
            }
        } catch(IllegalStateException ise) {
            Assert.notReached();
            return null;
        } catch(org.mozilla.jss.crypto.IllegalBlockSizeException ibse) {
            throw new IllegalBlockSizeException(ibse.getMessage());
        } catch(org.mozilla.jss.crypto.BadPaddingException bpe) {
            throw new BadPaddingException(bpe.getMessage());
        } catch(TokenException te) {
            throw new TokenRuntimeException(te.getMessage());
        }
    }

    public int engineDoFinal(byte[] input, int inputOffset, int inputLen,
        byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException,
            BadPaddingException
    {
        byte[] bytes = engineDoFinal(input, inputOffset, inputLen);
        if( bytes.length > output.length-outputOffset ) {
            throw new ShortBufferException(bytes.length +  " needed, " +
                (output.length-outputOffset) + " supplied");
        }
        System.arraycopy(bytes, 0, output, outputOffset, bytes.length);
        return bytes.length;
    }

    public byte[] engineWrap(Key key)
        throws IllegalBlockSizeException, InvalidKeyException
    {
        if( wrapper == null ) {
            Assert.notReached();
            return null;
        }
        try {
            if( key instanceof org.mozilla.jss.crypto.PrivateKey ) {
                return wrapper.wrap( (org.mozilla.jss.crypto.PrivateKey) key);
            } else if( key instanceof org.mozilla.jss.crypto.SecretKeyFacade) {
                return wrapper.wrap(
                    ((org.mozilla.jss.crypto.SecretKeyFacade)key).key );
            } else {
                throw new InvalidKeyException("Unsupported key type: " +
                    key.getClass().getName());
            }
        } catch(IllegalStateException ise) {
            // Cipher is supposed to catch this
            Assert.notReached();
            return null;
        } catch(TokenException te) {
            throw new TokenRuntimeException(te.getMessage());
        }
    }

    public Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm,
            int wrappedKeyType)
        throws InvalidKeyException, NoSuchAlgorithmException
    {
        if( wrapper == null ) {
            Assert.notReached();
            return null;
        }
        try {
            switch(wrappedKeyType) {
              case Cipher.SECRET_KEY:
                return engineUnwrapSecret(wrappedKey, wrappedKeyAlgorithm);
              case Cipher.PRIVATE_KEY:
                return engineUnwrapPrivate(wrappedKey, wrappedKeyAlgorithm);
              case Cipher.PUBLIC_KEY:
                throw new UnsupportedOperationException(
                    "Unable to unwrap public keys");
              default:
                throw new NoSuchAlgorithmException(
                    "Invalid key type: " + wrappedKeyType);
            }
        } catch(IllegalStateException ise) {
            // Cipher is supposed to catch this
            Assert.notReached();
            return null;
        }
    }

    private Key engineUnwrapSecret(byte[] wrappedKey, String wrappedKeyAlg)
        throws InvalidKeyException, NoSuchAlgorithmException
    {
        try {
            int idx = wrappedKeyAlg.indexOf('/');
            if( idx != -1 ) {
                wrappedKeyAlg = wrappedKeyAlg.substring(0, idx);
            }

            SymmetricKey.Type wrappedKeyType =
                SymmetricKey.Type.fromName(wrappedKeyAlg);

            // Specify 0 for key length. This will use the default key length.
            // Won't work for algorithms without a default, like RC4, unless a
            // padded algorithm is used.
            SymmetricKey key =
                wrapper.unwrapSymmetric(wrappedKey, wrappedKeyType, 0);

            return new SecretKeyFacade(key);
        } catch(StringIndexOutOfBoundsException e) {
            throw new NoSuchAlgorithmException("Unknown algorithm: " +
                wrappedKeyAlg);
        } catch(TokenException te ) {
            throw new TokenRuntimeException(te.getMessage());
        } catch(InvalidAlgorithmParameterException iape ) {
            throw new NoSuchAlgorithmException("Invalid algorithm parameters" +
                iape.getMessage());
        }
    }

    private Key engineUnwrapPrivate(byte[] wrappedKey, String wrappedKeyAlg)
        throws InvalidKeyException, NoSuchAlgorithmException
    {
        throw new NoSuchAlgorithmException(
            "Unwrapping private keys via the JCA interface is not supported: "+
            "http://bugzilla.mozilla.org/show_bug.cgi?id=135328");
    }

    public int engineGetKeySize(Key key) throws InvalidKeyException {
        if( key instanceof PK11PrivKey ) {
            return ((PK11PrivKey)key).getStrength();
        } else if( key instanceof PK11PubKey ) {
            try {
                byte[] encoded = ((PK11PubKey)key).getEncoded();
                SubjectPublicKeyInfo.Template spkiTemp =
                    new SubjectPublicKeyInfo.Template();
                SubjectPublicKeyInfo spki = (SubjectPublicKeyInfo)
                    ASN1Util.decode(spkiTemp, encoded);
                BIT_STRING pk = spki.getSubjectPublicKey();
                return pk.getBits().length - pk.getPadCount();
            } catch(InvalidBERException e) {
                throw new InvalidKeyException("Exception while decoding " +
                    "public key: " + e.getMessage());
            }
        } else if( key instanceof SecretKeyFacade ) {
            SymmetricKey symkey = ((SecretKeyFacade)key).key;
            return symkey.getLength();
        } else {
            key = importKey(key);
            SymmetricKey symkey = ((SecretKeyFacade)key).key;
            return symkey.getLength();
        }
    }

    static public class DES extends JSSCipherSpi {
        public DES() {
            super("DES");
        }
    }
    static public class DESede extends JSSCipherSpi {
        public DESede() {
            super("DESede");
        }
    }
    static public class AES extends JSSCipherSpi {
        public AES() {
            super("AES");
        }
    }
    static public class RC4 extends JSSCipherSpi {
        public RC4() {
            super("RC4");
        }
    }
    static public class RSA extends JSSCipherSpi {
        public RSA() {
            super("RSA");
        }
    }
    static public class RC2 extends JSSCipherSpi {
        public RC2() {
            super("RC2");
        }
    }

}
