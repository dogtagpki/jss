package org.mozilla.jss.crypto;

import java.math.BigInteger;

import org.mozilla.jss.ssl.SSLProtocolVariant;
import org.mozilla.jss.ssl.SSLSocket;
import org.mozilla.jss.ssl.SSLVersion;
import org.mozilla.jss.ssl.SSLVersionRange;

/**
 * This class helps JSS callers align with local system cryptographic policy.
 *
 * In the event of a policy violation, applications can override policy by
 * writing to the desired variable.
 *
 * Refer to SSLCipher.isSupported() for whether or not a given TLS cipher
 * suite is allowed by local policy.
 */
public class Policy {
    /**
     * Whether or not this JSS instance is enforcing local crypto-policy,
     * with respect to key sizes.
     *
     * Defaults to false; this lets applications use whatever key sizes are
     * supported by NSS, at the risk of performing non-compliant operations.
     * Set to true to enable enforcement, where it exists.
     */
    public static boolean ENFORCING_KEY_SIZES = false;

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

    public static SSLVersionRange TLS_VERSION_RANGE = getTLSVersionRange();

    public static SSLVersion TLS_MINIMUM_VERSION = TLS_VERSION_RANGE.getMinVersion();

    public static SSLVersion TLS_MAXIMUM_VERSION = TLS_VERSION_RANGE.getMaxVersion();

    private static SSLVersionRange getTLSVersionRange() {
        SSLVersionRange range = new SSLVersionRange(SSLVersion.minSupported(),
                                                    SSLVersion.maxSupported());
        try {
            return SSLSocket.boundSSLVersionRange(SSLProtocolVariant.STREAM, range);
        } catch (Exception e) {
            return range;
        }
    }

    private static native int getRSAMinimumKeySize();
    private static native int getDHMinimumKeySize();
    private static native int getDSAMinimumKeySize();
}
