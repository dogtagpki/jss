/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.pkcs11;

import org.mozilla.jss.crypto.*;
import java.security.DigestException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;

/**
 * Message Digesting with PKCS #11.
 */
public final class PK11MessageDigest extends JSSMessageDigest {

    private PK11Token token;
    private CipherContextProxy digestProxy;
    private PK11SymKey hmacKey;
    private DigestAlgorithm alg;

    PK11MessageDigest(PK11Token token, DigestAlgorithm alg)
        throws NoSuchAlgorithmException, DigestException
    {
        this.token = token;
        this.alg = alg;

        if( ! token.doesAlgorithm(alg) ) {
            throw new NoSuchAlgorithmException();
        }

        reset();
    }

    public void initHMAC(SymmetricKey key)
        throws DigestException, InvalidKeyException
    {

        if( ! (alg instanceof HMACAlgorithm) ) {
            throw new DigestException("Digest is not an HMAC digest");
        }

        reset();

        if( ! (key instanceof PK11SymKey) ) {
            throw new InvalidKeyException("HMAC key is not a PKCS #11 key");
        }

        hmacKey = (PK11SymKey) key;

        if( ! key.getOwningToken().equals(token) ) {
            hmacKey = null;
            throw new InvalidKeyException(
                "HMAC key does not live on the same token as this digest");
        }

        this.digestProxy = initHMAC(token, alg, hmacKey);
    }

    public void update(byte[] input, int offset, int len)
        throws DigestException
    {
        if( digestProxy == null ) {
            throw new DigestException("Digest not correctly initialized");
        }
        if( input.length < offset+len ) {
            throw new IllegalArgumentException(
                "Input buffer is not large enough for offset and length");
        }

        update(digestProxy, input, offset, len);
    }

    public int digest(byte[] outbuf, int offset, int len)
        throws DigestException
    {
        if( digestProxy == null ) {
            throw new DigestException("Digest not correctly initialized");
        }
        if( outbuf.length < offset+len ) {
            throw new IllegalArgumentException(
                "Output buffer is not large enough for offset and length");
        }

        int retval = digest(digestProxy, outbuf, offset, len);

        reset();

        return retval;
    }

    public void reset() throws DigestException {
        if( ! (alg instanceof HMACAlgorithm) ) {
            // This is a regular digest, so we have enough information
            // to initialize the context
            this.digestProxy = initDigest(alg);
        } else if( hmacKey != null ) {
            // This is an HMAC digest, and we have a key
            this.digestProxy = initHMAC(token, alg, hmacKey);
        } else {
            // this is an HMAC digest for which we don't have the key yet,
            // we have to wait to construct the context
            this.digestProxy = null;
        }
    }

    public DigestAlgorithm getAlgorithm() {
        return alg;
    }

    private static native CipherContextProxy
    initDigest(DigestAlgorithm alg)
        throws DigestException;

    private static native CipherContextProxy
    initHMAC(PK11Token token, DigestAlgorithm alg, PK11SymKey key)
        throws DigestException;

    private static native void
    update(CipherContextProxy proxy, byte[] inbuf, int offset, int len);

    private static native int
    digest(CipherContextProxy proxy, byte[] outbuf, int offset, int len);

}
