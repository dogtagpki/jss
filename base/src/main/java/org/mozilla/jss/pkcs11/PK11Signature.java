/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PSSParameterSpec;

import org.mozilla.jss.crypto.Algorithm;
import org.mozilla.jss.crypto.DigestAlgorithm;
import org.mozilla.jss.crypto.NoSuchItemOnTokenException;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.util.NativeProxy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class PK11Signature
    extends org.mozilla.jss.crypto.SignatureSpi
    implements java.lang.AutoCloseable
{

    public static final String NO_TOKEN = "No token provided";
    public static final String NO_TOKEN_PROXY = "No tokenProxy provided";
    public static final String NO_ALGORTIHM = "No algorithm provided";
    public static final String NO_KEY = "No key provided";
    public static final String NO_CONTEXT = "Signature has no context";
    public static final String SIG_NOT_INITIALIZED = "Signature is not initialized";
    public static final String NO_INPUT_STREAM = "Raw signature has no input stream";

    public PK11Signature(PK11Token token, SignatureAlgorithm algorithm)
        throws NoSuchAlgorithmException, TokenException
    {
        if (token == null) {
            throw new TokenException(NO_TOKEN);
        }
        if (algorithm == null) {
            throw new NoSuchAlgorithmException(NO_ALGORTIHM);
        }

        // Make sure this token supports this algorithm.  It's OK if
        // it only supports the signing part; the hashing can be done
        // on the internal module.
        if( ! token.doesAlgorithm(algorithm)  &&
            ! token.doesAlgorithm(algorithm.getSigningAlg()) )
        {
            throw new NoSuchAlgorithmException();
        }

        this.tokenProxy = token.getProxy();
        if (tokenProxy == null) {
            throw new TokenException(NO_TOKEN_PROXY);
        }
        this.token = token;
        this.algorithm = algorithm;
        this.digestAlgorithm = null;

        /*
         * A RSAPSSSignature would appear like "raw", because the algorithm
         * matches the raw algorithm type, but we need additional parameters.
         */
        if (!isRSAPSSAlgorithm(algorithm) && algorithm.getRawAlg() == algorithm) {
            raw = true;
            rawInput = new ByteArrayOutputStream();
        }
        this.state = UNINITIALIZED;

        // If we are using RSA-PSS, save the digest algorithm to be used by
        // the native code.
        if (isRSAPSSAlgorithm(algorithm)) {
            try {
                digestAlgorithm = algorithm.getDigestAlg();
            } catch (NoSuchAlgorithmException e) {
                digestAlgorithm = null;
            }
        }
    }

	@Override
    public void engineInitSign(org.mozilla.jss.crypto.PrivateKey privateKey)
		throws InvalidKeyException, TokenException
	{
        PK11PrivKey privKey;

        //
        // Scrutinize the key. Make sure it:
        //  -is a PKCS #11 key
        //  -lives on this token
        //  -is the right type for the algorithm
        //
		if( privateKey == null ) {
			throw new InvalidKeyException("private key is null");
		}
		if( ! (privateKey instanceof PK11PrivKey) ) {
			throw new InvalidKeyException("privateKey is not a PKCS #11 "+
				"private key");
		}

        privKey = (PK11PrivKey) privateKey;

        try {
    		privKey.verifyKeyIsOnToken(token);
        } catch(NoSuchItemOnTokenException e) {
            throw new InvalidKeyException(e.toString());
        }

        try {
            if( KeyType.getKeyTypeFromAlgorithm(algorithm)
                             != privKey.getKeyType())
            {
                throw new InvalidKeyException(
                    "Key type is inconsistent with algorithm");
            }
        } catch( NoSuchAlgorithmException e ) {
            throw new InvalidKeyException("Unknown algorithm: " + algorithm, e);
        }

        // Finally, the key is OK
		key = privKey;

        // Now initialize the signature context
        if( ! raw ) {
            sigContext = null;
            initSigContext();
        }

        // Don't set state until we know everything worked
		state = SIGN;
	}

    /*************************************************************
    ** This is just here for JCA compliance, we don't take randoms this way.
    */
	@Override
    public void
    engineInitSign(org.mozilla.jss.crypto.PrivateKey privateKey,
                    SecureRandom random)
		throws InvalidKeyException, TokenException
	{
		throw new RuntimeException("PK11Signature.engineInitSign() is not supported");

		// engineInitSign(privateKey);
	}

    /*************************************************************
    ** Creates a signing context, initializes it,
    ** and sets the sigContext field.
    */
    protected native void initSigContext()
        throws TokenException;


	@Override
    public void engineInitVerify(PublicKey publicKey)
		throws InvalidKeyException, TokenException
	{
		PK11PubKey pubKey;

        //
        // Scrutinize the key. Make sure it:
        //  -is a PKCS #11 key
        //  -lives on this token
        //  -is the right type for the algorithm
        //
		if( ! (publicKey instanceof PK11PubKey) ) {
			throw new InvalidKeyException("publicKey is not a PKCS #11 "+
				"public key");
		}
		pubKey = (PK11PubKey) publicKey;

        try {
            if( KeyType.getKeyTypeFromAlgorithm(algorithm)
                             != pubKey.getKeyType())
            {
                throw new InvalidKeyException(
                    "Key type is inconsistent with algorithm");
            }
        } catch( NoSuchAlgorithmException e ) {
            throw new InvalidKeyException("Unknown algorithm: " + algorithm, e);
        }

		key = pubKey;

        if( ! raw ) {
            sigContext = null;
            initVfyContext();
        }

        // Don't set state until we know everything worked.
		state = VERIFY;
	}

    protected native void initVfyContext() throws TokenException;

	@Override
    public void engineUpdate(byte b)
        throws SignatureException, TokenException
    {
        engineUpdate(new byte[] {b}, 0, 1);
    }

    @Override
    public void engineUpdate(byte[] b, int off, int len)
        throws SignatureException, TokenException
    {
        if (b == null) {
            throw new SignatureException("No byte provided");
        }
        validateUpdate();
        if (raw) {
            rawInput.write(b, off, len);
        } else {
            engineUpdateNative( b, off, len);
        }
    }

    private void validateUpdate() throws SignatureException {
        if (state == SIGN || state == VERIFY) {
            if (!raw && sigContext == null) {
                throw new SignatureException(NO_CONTEXT);
            } else if (raw && rawInput == null) {
                throw new SignatureException(NO_INPUT_STREAM);
            }
        } else {
            if (state == UNINITIALIZED) {
                throw new SignatureException(SIG_NOT_INITIALIZED);
            }
        }
        if (key == null) {
            throw new SignatureException(NO_KEY);
        }
    }

    protected native void engineUpdateNative(byte[] b, int off, int len)
        throws TokenException;


    @Override
    public byte[] engineSign()
        throws SignatureException, TokenException
    {
        if(state != SIGN) {
            throw new SignatureException(SIG_NOT_INITIALIZED);
        }
        if(!raw && sigContext==null) {
            throw new SignatureException(NO_CONTEXT);
        } else if(raw && rawInput==null) {
            throw new SignatureException(NO_INPUT_STREAM);
        }
        if (key == null) {
            throw new SignatureException(NO_KEY);
        }

        byte[] result;
        if( raw ) {
            result = engineRawSignNative(token, (PK11PrivKey)key,
                rawInput.toByteArray());
            rawInput.reset();
        } else {
            result = engineSignNative();
        }
		state = UNINITIALIZED;
		sigContext = null;

		return result;
    }

    @Override
    public int engineSign(byte[] outbuf, int offset, int len)
        throws SignatureException, TokenException
    {
        if (outbuf == null) {
            throw new SignatureException("No output buffer provided");
        }
        byte[] sig;
        if (raw) {
            sig = engineRawSignNative(token, (PK11PrivKey)key,
                rawInput.toByteArray());
            rawInput.reset();
        } else {
            sig = engineSign();
        }
        if (outbuf.length <= offset || len < sig.length || offset + len > outbuf.length) {
            throw new SignatureException("outbuf is not sufficient to hold signature");
        }
        System.arraycopy( sig, 0, outbuf, offset, sig.length);
        return sig.length;
    }

    /**
     * Performs raw signing of the given hash with the given private key.
     */
    private static native byte[] engineRawSignNative(PK11Token token,
        PrivateKey key, byte[] hash)
        throws SignatureException, TokenException;

    private native byte[] engineSignNative()
        throws SignatureException, TokenException;

    @Override
    public boolean engineVerify(byte[] sigBytes)
        throws SignatureException, TokenException
    {
        if (sigBytes == null) {
            throw new SignatureException("No signature bytes provided");
        }
        if(state != VERIFY) {
            throw new SignatureException("Signature is not initialized properly");
            }
        if(!raw && sigContext == null) {
            throw new SignatureException(NO_CONTEXT);
            }
        if(raw && rawInput == null) {
            throw new SignatureException(NO_INPUT_STREAM);
        }
        if (key == null) {
            throw new SignatureException(NO_KEY);
        }

        boolean result;
        if( raw ) {
            result = engineRawVerifyNative(token, (PK11PubKey)key,
                rawInput.toByteArray(), sigBytes);
            rawInput.reset();
        } else {
            result = engineVerifyNative(sigBytes);
        }
		state = UNINITIALIZED;
		sigContext = null;

		return result;
    }

    /**
     * Performs raw verification of the signature of a hash using the
     * given public key, on the given token.
     */
    protected static native boolean engineRawVerifyNative(PK11Token token,
        PublicKey key, byte[] hash, byte[] signature)
        throws SignatureException, TokenException;

	protected native boolean engineVerifyNative(byte[] sigBytes)
		throws SignatureException, TokenException;

    @Override
    public void engineSetParameter(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException, TokenException
    {
        // For now we only care about RSA PSS parameter specs
        if (!isRSAPSSAlgorithm((SignatureAlgorithm) algorithm)) {
            String msg = "Passing algorithm parameters for this algorithm (";
            msg += algorithm + ") is not supported: " + params.toString();
            throw new InvalidAlgorithmParameterException(msg);
        }

        if (!(params instanceof PSSParameterSpec)) {
            String msg = "Unsupported algorithm parameter spec class for ";
            msg += "RSA/PSS: " + params.getClass().getName() + " -- ";
            msg += params.toString();
            throw new InvalidAlgorithmParameterException(msg);
        }

        digestAlgorithm = getRSAPSSDigestAlgFromSpec((PSSParameterSpec) params);
    }

    private Algorithm getRSAPSSDigestAlgFromSpec(PSSParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        String hashAlgName = params.getDigestAlgorithm();
        Algorithm hashAlg = null;

        if (hashAlgName.equals("SHA-256")) {
            hashAlg = DigestAlgorithm.SHA256;
        } else if (hashAlgName.equals("SHA-384")) {
            hashAlg = DigestAlgorithm.SHA384;
        } else if (hashAlgName.equals("SHA-512")) {
            hashAlg = DigestAlgorithm.SHA512;
        } else {
            String msg = "This digest algorithm (" + hashAlgName + ") isn't ";
            msg += "supported for this algorithm (" + algorithm + "): ";
            msg += params.toString();
            throw new InvalidAlgorithmParameterException(msg);
        }

        return hashAlg;
    }

    private boolean isRSAPSSAlgorithm(SignatureAlgorithm algorithm) {
        if (algorithm == null) {
            return false;
        }

        return algorithm == SignatureAlgorithm.RSAPSSSignatureWithSHA256Digest
            || algorithm == SignatureAlgorithm.RSAPSSSignatureWithSHA384Digest
            || algorithm == SignatureAlgorithm.RSAPSSSignatureWithSHA512Digest
            || algorithm == SignatureAlgorithm.RSAPSSSignature;
    }

    @Override
    public void finalize() throws Throwable {
        close();
    }

    @Override
    public void close() throws Exception {
        if (sigContext != null) {
            try {
                sigContext.close();
            } finally {
                sigContext = null;
            }
        }
    }

    protected PK11Token token;
    protected TokenProxy tokenProxy;
    protected Algorithm algorithm;
    protected Algorithm digestAlgorithm;
    protected PK11Key key;
    protected int state;
    protected SigContextProxy sigContext;
    protected boolean raw=false; // raw signing only, no hashing
    protected ByteArrayOutputStream rawInput;

    // states
    public static final int UNINITIALIZED = 0;
    public static final int SIGN = 1;
    public static final int VERIFY = 2;
}

class SigContextProxy extends NativeProxy {

    public static Logger logger = LoggerFactory.getLogger(SigContextProxy.class);

    public SigContextProxy(byte[] pointer) {
        super(pointer);
    }
    @Override
    protected native void releaseNativeResources();
}
