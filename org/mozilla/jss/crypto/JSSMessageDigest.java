/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

import java.security.DigestException;
import java.security.InvalidKeyException;

/**
 * A class for performing message digesting (hashing) and MAC operations.
 */
public abstract class JSSMessageDigest {

    /**
     * Initializes an HMAC digest with the given symmetric key. This also
     *  has the effect of resetting the digest.
     *
     * @exception DigestException If this algorithm is not an HMAC algorithm.
     * @exception InvalidKeyException If the given key is not valid.
     */
    public abstract void initHMAC(SymmetricKey key)
        throws DigestException, InvalidKeyException;

    /**
     * Updates the digest with a single byte of input.
     */
    public void update(byte input) throws DigestException {
        byte[] in = { input };
        update(in, 0, 1);
    }

    /**
     * Updates the digest with a portion of an array.
     *
     * @param input An array from which to update the digest.
     * @param offset The index in the array at which to start digesting.
     * @param len The number of bytes to digest.
     * @exception DigestException If an error occurs while digesting.
     */
    public abstract void update(byte[] input, int offset, int len)
        throws DigestException;

    /**
     * Updates the digest with an array.
     *
     * @param input An array to feed to the digest.
     * @exception DigestException If an error occurs while digesting.
     */
    public void update(byte[] input) throws DigestException {
        update(input, 0, input.length);
    }

    /**
     * Completes digestion.
     * 
     * @return The, ahem, output of the digest operation.
     * @exception DigestException If an error occurs while digesting.
     */
    public byte[] digest() throws DigestException {
        byte[] output = new byte[getOutputSize()];
        digest(output, 0, output.length);
        return output;
    }

    /**
     * Completes digesting, storing the result into the provided array.
     *
     * @param buf The buffer in which to place the digest output.
     * @param offset The offset in the buffer at which to store the output.
     * @param len The amount of space available in the buffer for the
     *      digest output.
     * @return The number of bytes actually stored into buf.
     * @exception DigestException If the provided space is too small for
     *      the digest, or an error occurs with the digest.
     */
    public abstract int digest(byte[] buf, int offset, int len)
        throws DigestException;

    /**
     * Provides final data to the digest, then completes it and returns the
     * output.
     *
     * @param input The digest's last meal.
     * @return The completed digest.
     * @exception DigestException If an error occurs while digesting.
     */
    public byte[] digest(byte[] input) throws DigestException {
        update(input);
        return digest();
    }

    /**
     * Resets this digest for further use.  This clears all input and
     * output streams. If this is an HMAC digest, the HMAC key is not
     * cleared.
     */
    public abstract void reset() throws DigestException;

    /**
     * Returns the algorithm that this digest uses.
     */
    public abstract DigestAlgorithm getAlgorithm();

    /**
     * Returns the length of the digest created by this digest's
     * digest algorithm.
     *
     * @return The size in bytes of the output of this digest.
     */
    public int getOutputSize() {
        return getAlgorithm().getOutputSize();
    }
}
