/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.mozilla.jss.crypto;

import java.security.spec.AlgorithmParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.security.InvalidKeyException;

public interface KeyWrapper {

    public void initWrap(SymmetricKey wrappingKey,
                            AlgorithmParameterSpec parameters)
        throws InvalidKeyException, InvalidAlgorithmParameterException;

    public void initWrap(PublicKey wrappingKey,
                            AlgorithmParameterSpec parameters)
        throws InvalidKeyException, InvalidAlgorithmParameterException;

    /**
     * For wrapping keys in plaintext.
     */
    public void initWrap()
        throws InvalidKeyException, InvalidAlgorithmParameterException;

    public void initUnwrap(SymmetricKey unwrappingKey,
                            AlgorithmParameterSpec parameters)
        throws InvalidKeyException, InvalidAlgorithmParameterException;

    public void initUnwrap(PrivateKey unwrappingKey,
                            AlgorithmParameterSpec parameters)
        throws InvalidKeyException, InvalidAlgorithmParameterException;

    /**
     * For plaintext-wrapped keys.
     */
    public void initUnwrap()
        throws InvalidKeyException, InvalidAlgorithmParameterException;

    public byte[] wrap(PrivateKey toBeWrapped)
        throws InvalidKeyException, IllegalStateException, TokenException;

    public byte[] wrap(SymmetricKey toBeWrapped)
        throws InvalidKeyException, IllegalStateException, TokenException;

    /**
     * Unwraps a private key, creating a permanent private key object.
     * A permanent private key object resides on a token until it is
     * explicitly deleted from the token.
     *
     * @param publicKey Used to calculate the key identifier that must be stored
     *  with the private key. Must be a <code>RSAPublicKey</code> or a
     *  <code>DSAPublicKey</code>.
     * @exception InvalidKeyException If the type of the public key does not
     *  match the type of the private key to be unwrapped.
     */
    public PrivateKey unwrapPrivate(byte[] wrapped, PrivateKey.Type type,
        PublicKey publicKey)
        throws TokenException, InvalidKeyException, IllegalStateException;

    /**
     * Unwraps a private key, creating a temporary private key object.
     * A temporary
     * private key is one that does not permanently reside on a token.
     * As soon as it is garbage-collected, it is gone forever.
     *
     * @param publicKey Used to calculate the key identifier that must be stored
     *  with the private key. Must be a <code>RSAPublicKey</code> or a
     *  <code>DSAPublicKey</code>.
     * @exception InvalidKeyException If the type of the public key does not
     *  match the type of the private key to be unwrapped.
     */
    public PrivateKey unwrapTemporaryPrivate(byte[] wrapped,
        PrivateKey.Type type, PublicKey publicKey)
        throws TokenException, InvalidKeyException, IllegalStateException;

    /**
     * @param keyLength The expected length of the key in bytes.  This is 
     *   only used for variable-length keys (RC4) and non-padding
     *   algorithms. Otherwise, it can be set to anything(like 0).
     * @param usage The operation the key will be used for after it is
     *   unwrapped. You have to specify this so that the key can be properly
     *   marked with the operation it supports. Some PKCS #11 tokens require
     *   that a key be marked for an operation before it can perform that
     *   operation.
     */
    public SymmetricKey unwrapSymmetric(byte[] wrapped, SymmetricKey.Type type,
        SymmetricKey.Usage usage, int keyLength)
        throws TokenException, IllegalStateException,
            InvalidAlgorithmParameterException;

    /**
     * Unwraps a key and allows it to be used for all operations.
     * @param keyLength The expected length of the key in bytes.  This is 
     *   only used for variable-length keys (RC4) and non-padding
     *   algorithms. Otherwise, it can be set to anything(like 0).
     */
    public SymmetricKey unwrapSymmetric(byte[] wrapped, SymmetricKey.Type type,
        int keyLength)
        throws TokenException, IllegalStateException,
            InvalidAlgorithmParameterException;

    public SymmetricKey unwrapSymmetricPerm(byte[] wrapped, SymmetricKey.Type type,
        SymmetricKey.Usage usage, int keyLength)
        throws TokenException, IllegalStateException,
            InvalidAlgorithmParameterException;

    /**
     * Unwraps a key and allows it to be used for all operations.
     * @param keyLength The expected length of the key in bytes.  This is
     *   only used for variable-length keys (RC4) and non-padding
     *   algorithms. Otherwise, it can be set to anything(like 0).
     */
    public SymmetricKey unwrapSymmetricPerm(byte[] wrapped, SymmetricKey.Type type,
        int keyLength)
        throws TokenException, IllegalStateException,
            InvalidAlgorithmParameterException;

}
