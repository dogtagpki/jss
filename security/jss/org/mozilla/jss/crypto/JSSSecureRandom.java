/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

/**
 * An interface for secure random numbers.
 * @deprecated Use the JCA interface instead ({@link java.security.SecureRandom})
 */
public interface JSSSecureRandom {

    /**
     * Seed the RNG with the given seed bytes.
     */
    public void setSeed(byte[] seed);

    /**
     * Seed the RNG with the eight bytes contained in <code>seed</code>.
     */
    public void setSeed(long seed);

    /**
     * Retrieves random bytes and stores them in the given array.
     */
    public void nextBytes(byte bytes[]);
}
