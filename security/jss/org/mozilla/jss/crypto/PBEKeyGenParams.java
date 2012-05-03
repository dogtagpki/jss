/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.crypto;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import org.mozilla.jss.util.Password;

public class PBEKeyGenParams implements AlgorithmParameterSpec, KeySpec {

    private Password pass;
    private byte[] salt;
    private int iterations;

    private PBEKeyGenParams() { }

    static private final int DEFAULT_SALT_LENGTH = 8;
    static private final int DEFAULT_ITERATIONS = 1;

    /**
     * Creates PBE parameters.
     *
     * @param pass The password. It will be cloned, so the
     *      caller is still responsible for clearing it. It must not be null.
     * @param salt The salt for the PBE algorithm. Will <b>not</b> be cloned.
     *      Must not be null. It is the responsibility of the caller to
     *      use the right salt length for the algorithm. Most algorithms
     *      use 8 bytes of salt.
     * @param The iteration count for the PBE algorithm.
     */
    public PBEKeyGenParams(Password pass, byte[] salt, int iterations) {
        if(pass==null || salt==null) {
            throw new NullPointerException();
        }
        this.pass = (Password) pass.clone();
        this.salt = salt;
        this.iterations = iterations;
    }

    /**
     * Creates PBE parameters.
     *
     * @param pass The password. It will be cloned, so the
     *      caller is still responsible for clearing it. It must not be null.
     * @param salt The salt for the PBE algorithm. Will <b>not</b> be cloned.
     *      Must not be null. It is the responsibility of the caller to
     *      use the right salt length for the algorithm. Most algorithms
     *      use 8 bytes of salt.
     * @param The iteration count for the PBE algorithm.
     */
    public PBEKeyGenParams(char[] pass, byte[] salt, int iterations) {
        if(pass==null || salt==null) {
            throw new NullPointerException();
        }
        this.pass = new Password( (char[]) pass.clone() );
        this.salt = salt;
        this.iterations = iterations;
    }

    /**
     * Returns a <b>reference</b> to the password, not a copy.
     */
    public Password getPassword() {
        return pass;
    }

    /**
     * Returns a <b>reference</b> to the salt.
     */
    public byte[] getSalt() {
        return salt;
    }

    /**
     * Returns the iteration count.
     */
    public int getIterations() {
        return iterations;
    }

    /**
     * Clears the password. This should be called when this object is no
     * longer needed so the password is not left around in memory.
     */
    public void clear() {
        pass.clear();
    }

    protected void finalize() throws Throwable {
        pass.clear();
    }
}
