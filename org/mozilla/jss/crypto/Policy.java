package org.mozilla.jss.crypto;

import java.math.BigInteger;

/**
 * This class helps JSS callers align with local system cryptographic policy.
 *
 * In the event of a policy violation, applications can override policy by
 * writing to the desired variable.
 */
public class Policy {
    /**
     * Minimum RSA key length in bits permitted by local policy.
     */
    public static int RSA_MINIMUM_KEY_SIZE = getRSAMinimumKeySize();

    /**
     * Minimum RSA public exponent allowed by JSS.
     */
    public static BigInteger RSA_MINIMUM_PUBLIC_EXPONENT = BigInteger.valueOf(65537);

    /**
     * Minimum DH key length in bits permitted by local policy.
     */
    public static int DH_MINIMUM_KEY_SIZE = getDHMinimumKeySize();

    /**
     * Minimum DSA key length in bits permitted by local policy.
     */
    public static int DSA_MINIMUM_KEY_SIZE = getDSAMinimumKeySize();

    private static native int getRSAMinimumKeySize();
    private static native int getDHMinimumKeySize();
    private static native int getDSAMinimumKeySize();
}
