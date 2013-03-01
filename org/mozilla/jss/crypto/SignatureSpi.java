/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.crypto;

import java.security.*;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * You don't need to use this unless you are hacking JSS.
 */
public abstract class SignatureSpi {

	public abstract void engineInitVerify(PublicKey publicKey)
		throws InvalidKeyException, TokenException;

	public abstract void engineInitSign(PrivateKey privateKey)
		throws InvalidKeyException, TokenException;

	public abstract void engineInitSign(PrivateKey privateKey,
										SecureRandom random)
		throws InvalidKeyException, TokenException;

	public abstract void engineUpdate(byte b)
        throws SignatureException, TokenException;

	public abstract void engineUpdate(byte[] b, int off, int len)
		throws SignatureException, TokenException;

	public abstract byte[] engineSign()
        throws SignatureException, TokenException;
 
	public abstract int engineSign(byte[] outbuf, int offset, int len)
		throws SignatureException, TokenException;

	public abstract boolean engineVerify(byte[] sigBytes)
		throws SignatureException, TokenException;

	public abstract void engineSetParameter(AlgorithmParameterSpec params)
		throws InvalidAlgorithmParameterException, TokenException;
}
