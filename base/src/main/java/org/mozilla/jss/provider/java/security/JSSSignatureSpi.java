/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.provider.java.security;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.TokenSupplierManager;

public class JSSSignatureSpi extends java.security.SignatureSpi {

    org.mozilla.jss.crypto.Signature sig;
    SignatureAlgorithm alg;
    AlgorithmParameterSpec paramSpec;

    protected JSSSignatureSpi(SignatureAlgorithm alg) {
        this.alg = alg;
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException();
    }

    @Override
    public void engineInitSign(java.security.PrivateKey privateKey,
        SecureRandom random) throws InvalidKeyException
    {
        // discard the random
        engineInitSign(privateKey);
    }

    @Override
    public void engineInitSign(java.security.PrivateKey privateKey)
        throws InvalidKeyException
    {
        try {
            sig = getSigContext(privateKey);
            if (paramSpec != null) {
                sig.setParameter(paramSpec);
            }
            sig.initSign((PrivateKey)privateKey);
        } catch(java.security.NoSuchAlgorithmException e) {
            throw new InvalidKeyException("Algorithm not supported: " + e.getMessage(), e);
        } catch(TokenException e) {
            throw new InvalidKeyException("Token exception occurred: " + e.getMessage(), e);
        } catch(InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException("AlgorithmParameterSpec not supported: " + e.getMessage(), e);
        }
    }

    private org.mozilla.jss.crypto.Signature
    getSigContext(java.security.PrivateKey privateKey)
        throws NoSuchAlgorithmException, InvalidKeyException, TokenException
    {
        CryptoToken token;
        PrivateKey privk;

        if( ! (privateKey instanceof PrivateKey) ) {
            throw new InvalidKeyException();
        }
        privk = (PrivateKey)privateKey;

        token = privk.getOwningToken();

        return token.getSignatureContext(alg);
    }

    @Override
    public void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        try {
            CryptoToken token =
              TokenSupplierManager.getTokenSupplier().getThreadToken();
            sig = token.getSignatureContext(alg);

            // convert the public key into a JSS public key if necessary
            if( ! (publicKey instanceof org.mozilla.jss.pkcs11.PK11PubKey) ) {
                if( ! publicKey.getFormat().equalsIgnoreCase("X.509") ) {
                    throw new InvalidKeyException(
                        "Unsupported public key format: " +
                        publicKey.getFormat());
                }
                X509EncodedKeySpec encodedKey =
                    new X509EncodedKeySpec(publicKey.getEncoded());
                KeyFactory fact = KeyFactory.getInstance(
                    publicKey.getAlgorithm(), "Mozilla-JSS");
                publicKey = fact.generatePublic(encodedKey);
            }

            sig.initVerify(publicKey);
        } catch(NoSuchProviderException e) {
            throw new InvalidKeyException("Unable to convert non-JSS key to JSS key: " + e.getMessage(), e);
        } catch(java.security.spec.InvalidKeySpecException e) {
            throw new InvalidKeyException("Unable to convert non-JSS key to JSS key: " + e.getMessage(), e);
        } catch(java.security.NoSuchAlgorithmException e) {
            throw new InvalidKeyException("Algorithm not supported: " + e.getMessage(), e);
        } catch(TokenException e) {
            throw new InvalidKeyException("Token exception occurred: " + e.getMessage(), e);
        }
    }

    @Override
    public void engineUpdate(byte b)
        throws SignatureException
    {
        try {
            sig.update(b);
        } catch( TokenException e) {
            throw new SignatureException("TokenException: "+e.toString());
        }
    }

    @Override
    public void engineUpdate(byte[] b, int off, int len)
        throws SignatureException
    {
        try {
            sig.update(b, off, len);
        } catch( TokenException e) {
            throw new SignatureException("TokenException: "+e.toString());
        }
    }

    @Override
    public byte[] engineSign() throws SignatureException {
        try {
            return sig.sign();
        } catch(TokenException e) {
            throw new SignatureException("TokenException: "+e.toString());
        }
    }

    @Override
    public int engineSign(byte[] outbuf, int offset, int len)
        throws SignatureException
    {
        try {
            return sig.sign(outbuf, offset, len);
        } catch(TokenException e) {
            throw new SignatureException("TokenException: "+e.toString());
        }
    }

    @Override
    public boolean engineVerify(byte[] sigBytes) throws SignatureException {
        try {
            return sig.verify(sigBytes);
        } catch( TokenException  e) {
            throw new SignatureException("TokenException: "+e.toString());
        }
    }

    @Override
    public void engineSetParameter(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        paramSpec = params;
    }

    @Override
    public Object engineGetParameter(String param)
            throws InvalidParameterException
    {
        throw new InvalidParameterException(
            "name/value parameters not supported");
    }

    @Override
    public void engineSetParameter(String param, Object value)
            throws InvalidParameterException
    {
        throw new InvalidParameterException(
            "name/value parameters not supported");
    }

    @Deprecated(since="5.0.1", forRemoval=true)
    public static class DSA extends JSSSignatureSpi {
        public DSA() {
            super(SignatureAlgorithm.DSASignatureWithSHA1Digest);
        }
    }
    @Deprecated(since="5.0.1", forRemoval=true)
    public static class SHA1EC extends JSSSignatureSpi {
        public SHA1EC() {
            super(SignatureAlgorithm.ECSignatureWithSHA1Digest);
        }
    }
    public static class SHA256EC extends JSSSignatureSpi {
        public SHA256EC() {
            super(SignatureAlgorithm.ECSignatureWithSHA256Digest);
        }
    }
    public static class SHA384EC extends JSSSignatureSpi {
        public SHA384EC() {
            super(SignatureAlgorithm.ECSignatureWithSHA384Digest);
        }
    }
    public static class SHA512EC extends JSSSignatureSpi {
        public SHA512EC() {
            super(SignatureAlgorithm.ECSignatureWithSHA512Digest);
        }
    }
    public static class MD2RSA extends JSSSignatureSpi {
        public MD2RSA() {
            super(SignatureAlgorithm.RSASignatureWithMD2Digest);
        }
    }
    public static class MD5RSA extends JSSSignatureSpi {
        public MD5RSA() {
            super(SignatureAlgorithm.RSASignatureWithMD5Digest);
        }
    }
    public static class SHA1RSA extends JSSSignatureSpi {
        public SHA1RSA() {
            super(SignatureAlgorithm.RSASignatureWithSHA1Digest);
        }
    }
    public static class SHA256RSA extends JSSSignatureSpi {
        public SHA256RSA() {
            super(SignatureAlgorithm.RSASignatureWithSHA256Digest);
        }
    }
    public static class SHA384RSA extends JSSSignatureSpi {
        public SHA384RSA() {
            super(SignatureAlgorithm.RSASignatureWithSHA384Digest);
        }
    }
    public static class SHA512RSA extends JSSSignatureSpi {
        public SHA512RSA() {
            super(SignatureAlgorithm.RSASignatureWithSHA512Digest);
        }
    }
    public static class RSAPSSSignature extends JSSSignatureSpi {
        public RSAPSSSignature() {
            super(SignatureAlgorithm.RSAPSSSignature);
        }
    }
    public static class SHA256RSAPSS extends JSSSignatureSpi {
        public SHA256RSAPSS() {
            super(SignatureAlgorithm.RSAPSSSignatureWithSHA256Digest);
        }
    }
    public static class SHA384RSAPSS extends JSSSignatureSpi {
        public SHA384RSAPSS() {
            super(SignatureAlgorithm.RSAPSSSignatureWithSHA384Digest);
        }
    }
    public static class SHA512RSAPSS extends JSSSignatureSpi {
        public SHA512RSAPSS() {
            super(SignatureAlgorithm.RSAPSSSignatureWithSHA512Digest);
        }
    }
}
